from classes import *
from zabbix_utils import AsyncZabbixAPI
from flask import Flask, render_template, request, redirect, url_for

app = Flask(__name__)

ZABBIX_SERVER = "127.0.0.1"     # Zabbix server URL or IP address
ZABBIX_USER = "Admin"           # Default user name for authentication
ZABBIX_PASSWORD = "zabbix"      # Default user password for authentication


@app.template_filter("islist")
def islist(value):
    """Check if the given value is a list.

    Args:
        value: The value to check.

    Returns:
        bool: True if value is a list, False otherwise.
    """
    return isinstance(value, list)


@app.template_filter("optype")
def optype(value):
    """Map operation types to human-readable names.

    Args:
        value: The operation type as a string.

    Returns:
        str: The human-readable operation type or 'unknown'
             if the type is not recognized.
    """
    optype_mapping = {"0": "problem", "1": "recovery", "2": "update"}
    return optype_mapping.get(value, "unknown")


app.jinja_env.filters.update({"islist": islist, "optype": optype})


@app.context_processor
def utility_processor():
    """Provide utility functions to Jinja2 templates."""

    def contains(array, item):
        """Check if the item is in the array.

        Args:
            array: The array to check.
            item: The item to find.

        Returns:
            bool: True if the item is in the array, False otherwise.
        """
        return item in array

    return dict(contains=contains)


app.jinja_env.globals.update(enumerate=enumerate)


async def get_trigger_recipients(api, hostid):
    """Fetch recipients for triggers associated with a specific host.

    Args:
        api: The instance of the AsyncZabbixAPI.
        hostid: The ID of the host for which to get triggers.

    Returns:
        dict: A dictionary mapping trigger IDs to Trigger objects,
              including their respective recipients.
    """
    triggers_metadata = {}
    messages = []
    user_groups = {}
    recipients = {}

    # Fetch triggers related to the specified host
    triggers = await api.trigger.get(
        hostids=[hostid],
        selectTags="extend",
        selectHosts=["hostid"],
        selectHostGroups=["groupid"],
        selectDiscoveryRule=["templateid"],
        output="extend",
    )

    # Store the triggers in the metadata dictionary
    for trigger in triggers:
        triggers_metadata[trigger["triggerid"]] = Trigger(trigger)

    # Fetch templates associated with the triggers
    templates = await api.template.get(
        triggerids=list(set([t.tmpl_triggerid for t in triggers_metadata.values()])),
        selectTriggers=["triggerid"],
        selectDiscoveries=["itemid"],
        output=["templateid"],
    )

    # Fetch actions for Zabbix alerts
    actions = await api.action.get(
        selectFilter="extend",
        selectOperations="extend",
        selectRecoveryOperations="extend",
        selectUpdateOperations="extend",
        filter={"eventsource": 0, "status": 0},
        output=["actionid", "esc_period", "eval_formula", "name"],
    )

    # Fetch media types used for alert delivery
    mediatypes = await api.mediatype.get(
        selectUsers="extend",
        selectActions="extend",
        selectMessageTemplates="extend",
        filter={"status": 0},
        output=["mediatypeid", "name"],
    )

    # Link triggers with their respective operations and messages
    for trigger in triggers_metadata.values():
        trigger.select_templates(templates)
        messages += trigger.select_operations(actions, mediatypes)

    userids = set()
    groupids = set()

    # Gather all unique user IDs and user group IDs from messages
    for message in messages:
        userids.update(message.users)
        groupids.update(message.groups)

    # Fetch all user groups
    usergroups = {
        group["usrgrpid"]: group
        for group in await api.usergroup.get(
            selectUsers=["userid"],
            selectHostGroupRights="extend",
            output=["usrgrpid", "role"],
        )
    }

    # Fetch all users
    users = {
        user["userid"]: user
        for user in await api.user.get(
            selectUsrgrps=["usrgrpid"],
            selectMedias=["mediatypeid", "active", "sendto"],
            selectRole=["roleid", "type"],
            filter={"status": 0},
            output=["userid", "username", "name", "surname"],
        )
    }

    # Create recipient objects for each user
    for userid in userids:
        if userid in users:
            user = users[userid]
            recipients[userid] = Recipient(user)
            for group in user["usrgrps"]:
                if group["usrgrpid"] in usergroups:
                    recipients[userid].permissions.update([
                        h["id"]
                        for h in usergroups[group["usrgrpid"]]["hostgroup_rights"]
                        if int(h["permission"]) > 1
                    ])

    # Populate user groups and associate recipients with their permissions
    for groupid in groupids:
        if groupid in usergroups:
            group = usergroups[groupid]
            user_groups[group["usrgrpid"]] = []
            for user in group["users"]:
                user_groups[group["usrgrpid"]].append(user["userid"])
                if user["userid"] in recipients:
                    recipients[user["userid"]].groups.update(group["usrgrpid"])
                elif user["userid"] in users:
                    recipients[user["userid"]] = Recipient(users[user["userid"]])
                recipients[user["userid"]].permissions.update([
                    h["id"]
                    for h in group["hostgroup_rights"]
                    if int(h["permission"]) > 1
                ])

    # Assign recipients to messages based on their group memberships
    for message in messages:
        message.select_recipients(user_groups, recipients)

    return triggers_metadata


@app.route("/", methods=["GET", "POST"])
async def index():
    error = None
    triggers = []
    global ZABBIX_SERVER, ZABBIX_USER, ZABBIX_PASSWORD

    # Flag to display users who do not have rights to the current host
    show_unavail = False

    # Retrieve server connection details from request form
    ZABBIX_SERVER = request.form.get("server", ZABBIX_SERVER)
    ZABBIX_USER = request.form.get("username", ZABBIX_USER)
    ZABBIX_PASSWORD = request.form.get("password", ZABBIX_PASSWORD)

    if hostid := request.form.get("hostid"):
        return redirect(url_for("index", hostid=hostid), code=302)
    elif not (hostid := request.args.get("hostid")):
        return render_template("index.html")

    try:
        # Initialize Zabbix API client and log in
        zapi = AsyncZabbixAPI(url=ZABBIX_SERVER, validate_certs=False)
        await zapi.login(user=ZABBIX_USER, password=ZABBIX_PASSWORD)
    except Exception as e:
        error = str(e)
        return render_template("index.html", error=error)

    # Retrieve data of the specified host
    hosts = await zapi.host.get(
        hostids=[hostid],
        output=["hostid", "name"],
    )
    if not hosts:
        return render_template("index.html", error="Host with the specified ID was not found")

    # Retrieve triggers and their recipients for the specified host
    triggers = await get_trigger_recipients(zapi, hostid)

    # Check if each recipient has the necessary permissions to receive messages
    for trigger in triggers.values():
        for message in trigger.messages:
            for recipient in message.recipients:
                recipient.show = True
                if not recipient.has_right:
                    recipient.has_right = (len([
                        gid
                        for gid in trigger.hostgroups
                        if gid in recipient.permissions
                    ]) > 0)
                if not recipient.has_right and not show_unavail:
                    recipient.show = False

    await zapi.logout()
    return render_template("recipients.html", host=hosts[0], triggers=triggers)


if __name__ == "__main__":
    app.run(debug=True)
