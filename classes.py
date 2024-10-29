import re
import copy


class Trigger:
    """Represents a Zabbix Trigger as a source of event and related alerts.

    Attributes:
        name: The name (description) of the trigger.
        triggerid: The unique identifier of the trigger.
        hostgroups: List of host group IDs associated with this trigger.
        hosts: List of host IDs associated with this trigger.
        tags: A dictionary of tags associated with the trigger.
        tmpl_triggerid: The template trigger ID if the trigger is based on a template.
        templates: List of template IDs the trigger is associated with.
        messages: List of Message objects generated from actions associated with the trigger.
        _conditions: A dictionary holding various condition types and their respective values.
    """

    def __init__(self, trigger):
        self.name = trigger["description"]
        self.triggerid = trigger["triggerid"]
        self.hostgroups = [g["groupid"] for g in trigger["hostgroups"]]
        self.hosts = [h["hostid"] for h in trigger["hosts"]]
        self.tags = {t["tag"]: t["value"] for t in trigger["tags"]}
        self.tmpl_triggerid = self.triggerid
        self.lld_rule = trigger["discoveryRule"] or {}
        # If this trigger is based on a template, set the template trigger ID
        if trigger["templateid"] != "0":
            self.tmpl_triggerid = trigger["templateid"]
        self.templates = []
        self.messages = []
        self._conditions = {
            '0': self.hostgroups,           # Condition type 0 corresponds to the host group check
            '1': self.hosts,                # Condition type 1 corresponds to the host check
            '2': [self.triggerid],          # Condition type 2 corresponds to the trigger ID check
            '3': trigger['event_name'] 
                or trigger['description'],  # Condition type 3 corresponds to the event name check
            '4': trigger['priority'],       # Condition type 4 corresponds to the check of the priority of the trigger
            '13': self.templates,           # Condition type 13 corresponds to the template check
            '25': self.tags.keys(),         # Condition type 25 corresponds to the tag name check
            '26': self.tags                 # Condition type 26 corresponds to the tag value check
        }

    def eval_condition(self, operator, value, trigger_data):
        """Evaluate a condition based on the operator and value against trigger data.

        Args:
            operator: The operator indicating the type of evaluation (e.g., equals, greater than, etc.).
            value: The value to compare against in the evaluation.
            trigger_data: The data received from the trigger context for evaluation.

        Returns:
            A boolean indicating whether the condition is satisfied.
        """

        # equals or does not equal
        if operator in ["0", "1"]:
            equals = operator == "0"
            if isinstance(value, dict) and isinstance(trigger_data, dict):
                if value["tag"] in trigger_data:
                    if value["value"] == trigger_data[value["tag"]]:
                        return equals
            elif value in trigger_data and isinstance(trigger_data, list):
                return equals
            elif value == trigger_data:
                return equals
            return not equals

        # contains or does not contain
        if operator in ["2", "3"]:
            contains = operator == "2"
            if isinstance(value, dict) and isinstance(trigger_data, dict):
                if value["tag"] in trigger_data:
                    if value["value"] in trigger_data[value["tag"]]:
                        return contains
            elif value in trigger_data:
                return contains
            return not contains

        # is greater/less than or equals
        if operator in ["5", "6"]:
            greater = operator != "5"
            try:
                if int(value) < int(trigger_data):
                    return not greater
                if int(value) == int(trigger_data):
                    return True
                if int(value) > int(trigger_data):
                    return greater
            except:
                raise ValueError("Values must be numbers to compare them")

    def select_templates(self, templates):
        """Select templates associated with the trigger based on the trigger ID.

        Args:
            templates: A list of templates to check against the trigger ID.
        """
        for template in templates:
            if self.tmpl_triggerid in [t["triggerid"] for t in template["triggers"]]:
                self.templates.append(template["templateid"])
            if self.lld_rule.get("templateid") in [
                d["itemid"] for d in template["discoveries"]
            ]:
                self.templates.append(template["templateid"])

    def select_actions(self, actions):
        """Select actions that match the conditions defined for this trigger.

        Args:
            actions: List of available actions to be evaluated against the trigger.

        Returns:
            A list of actions that are selected based on the conditions of this trigger.
        """

        selected_actions = []
        for action in actions:
            conditions = []
            if "filter" in action:
                conditions = action["filter"]["conditions"]
                eval_formula = action["filter"]["eval_formula"]

            # Add actions without conditions directly
            if not conditions:
                selected_actions.append(action)
                continue
            condition_check = {}
            for condition in conditions:
                # Skip condition types - time period, is suppressed
                if (condition["conditiontype"] != "6" and condition["conditiontype"] != "16"):
                    if condition["conditiontype"] == "26" and isinstance(condition["value"], str):
                        condition["value"] = {"tag": condition["value2"], "value": condition["value"]}
                    if condition["conditiontype"] in self._conditions:
                        # Evaluate the condition with the appropriate operator
                        condition_check[condition["formulaid"]] = self.eval_condition(condition["operator"], condition["value"], self._conditions[condition["conditiontype"]])
                else:
                    condition_check[condition["formulaid"]] = True
            for formulaid, bool_result in condition_check.items():
                eval_formula = eval_formula.replace(formulaid, str(bool_result))

            # Evaluate the final condition formula
            if eval(eval_formula):
                selected_actions.append(action)

        return selected_actions

    def select_operations(self, actions, mediatypes):
        """Select operations for the given actions.

        Args:
            actions: A list of actions to be processed.
            mediatypes: A list of available media types for the actions.

        Returns:
            A list of message metadata for the selected operations.
        """

        messages_metadata = []
        for action in self.select_actions(actions):
            # Check operations for different event types
            messages_metadata += self.check_operations("operations", action, mediatypes)
            messages_metadata += self.check_operations("update_operations", action, mediatypes)
            messages_metadata += self.check_operations("recovery_operations", action, mediatypes)

        return messages_metadata

    def check_operations(self, optype, action, mediatypes):
        """Check and prepare alerts for the specified type of operation.

        Args:
            optype: The type of operation (e.g., 'operations', 'recovery_operations').
            action: The action to process for operations.
            mediatypes: List of media types for sending messages.

        Returns:
            A list of message metadata prepared for sending alerts.
        """

        messages_metadata = []
        optype_mapping = {
            "operations": "0",           # Problem event
            "recovery_operations": "1",  # Recovery event
            "update_operations": "2",    # Update event
        }
        # Create a copy of operations to avoid altering the original
        operations = copy.deepcopy(action[optype])

        # Processing "notify all involved" scenarios
        for idx, _ in enumerate(operations):
            if operations[idx]["operationtype"] not in ["11", "12"]:
                continue
            # Copy operation as a template for reuse
            op_template = copy.deepcopy(operations[idx])
            del operations[idx]
            # Checking for message sending operations
            for key in [k for k in ["operations", "update_operations"] if k != optype]:
                if not action[key]:
                    continue
                # Checking for message sending type operations
                for op in [o for o in action[key] if o["operationtype"] == "0"]:
                    # Copy template for the current operation
                    operation = copy.deepcopy(op_template)
                    operation.update({
                        "operationtype": "0",
                        "opmessage_usr": op["opmessage_usr"],
                        "opmessage_grp": op["opmessage_grp"],
                    })
                    operation["opmessage"]["mediatypeid"] = op["opmessage"]["mediatypeid"]
                    operations.append(operation)

        for operation in operations:
            # Skip operations that are not message sending type operations
            if operation["operationtype"] != "0":
                continue
            # Processing "all mediatypes" scenario
            if operation["opmessage"]["mediatypeid"] == "0":
                for mediatype in mediatypes:
                    operation["opmessage"]["mediatypeid"] = mediatype["mediatypeid"]
                    messages_metadata.append(
                        self.create_messages(
                            optype_mapping[optype], action, operation, [mediatype]
                        )
                    )
            else:
                messages_metadata.append(
                    self.create_messages(
                        optype_mapping[optype], action, operation, mediatypes
                    )
                )

        return messages_metadata

    def create_messages(self, optype, action, operation, mediatypes):
        """Create a message instance and append it to the messages list.

        Args:
            optype: The type of operation being performed (problem, recovery, or update).
            action: The action that triggered the message creation.
            operation: The operation details used for generating messages.
            mediatypes: The media types used to send messages.

        Returns:
            The created message instance.
        """

        message = Message(optype, action, operation)
        message.select_mediatypes(mediatypes)
        self.messages.append(message)

        return message


class Message:
    """Represents a message sent by Zabbix as a part of an action operation.

    Attributes:
        optype: The operation type (0: problem, 1: recovery, 2: update).
        mediatypename: The name of the media type used to send the message.
        actionid: The ID of the action that triggered this message.
        actionname: The name of the corresponding action.
        operationid: The ID of the operation that generated the message.
        mediatypeid: The media type ID used for the message.
        subject: The subject line for the message.
        message: The body content of the message.
        default_msg: Indicates if a default message is being used.
        users: List of user IDs to receive the message.
        groups: List of user group IDs to which the users belong.
        recipients: List of Recipient objects that represent users that will receive the message.
        esc_period: The escalation period for the message.
        esc_step_from: The starting step for message escalation.
        repeat_count: The number of times to send the message.
    """

    def __init__(self, optype, action, operation):
        self.optype = optype
        self.mediatypename = ""
        self.actionid = action["actionid"]
        self.actionname = action["name"]
        self.operationid = operation["operationid"]
        self.mediatypeid = operation["opmessage"]["mediatypeid"]
        self.subject = operation["opmessage"]["subject"]
        self.message = operation["opmessage"]["message"]
        self.default_msg = operation["opmessage"]["default_msg"]
        self.users = [u["userid"] for u in operation["opmessage_usr"]]
        self.groups = [g["usrgrpid"] for g in operation["opmessage_grp"]]
        self.recipients = []
        # Escalation period set to action's period if not specified
        self.esc_period = operation.get("esc_period", "0")
        if self.esc_period == "0":
            self.esc_period = action["esc_period"]
        # Use action's escalation period if unset
        self.esc_step_from = self.multiply_time(
            self.esc_period, int(operation.get("esc_step_from", "1")) - 1
        )
        if operation.get("esc_step_to", "0") != "0":
            self.repeat_count = str(
                int(operation["esc_step_to"]) - int(operation["esc_step_from"]) + 1
            )
        # If not a problem event, set repeat count to 1
        elif self.optype != "0":
            self.repeat_count = "1"
        # Infinite repeat count if esc_step_to is 0
        else:
            self.repeat_count = "&infin;"

    def multiply_time(self, time_str, multiplier):
        """Multiply time strings by a given multiplier.

        Args:
            time_str: The time string to multiply.
            multiplier: The multiplier to apply to each numeric component of the time string.

        Returns:
            The modified time string after multiplication.
        """

        # Multiply numbers within the time string
        result = re.sub(r"(\d+)", lambda m: str(int(m.group(1)) * multiplier), time_str)
        if result[0] == "0":
            return "0"
        return result

    def select_mediatypes(self, mediatypes):
        """Select appropriate media types for the message based on the operation details.

        Args:
            mediatypes: List of available media types to check against the message operation details.
        """
        for mediatype in mediatypes:
            if mediatype["mediatypeid"] == self.mediatypeid:
                self.mediatypename = mediatype["name"]
                # Select message templates related to operation type
                msg_template = [
                    m
                    for m in mediatype["message_templates"]
                    if m["recovery"] == self.optype and m["eventsource"] == "0"
                ]
                # Use default message if applicable
                if msg_template and self.default_msg == "1":
                    self.subject = msg_template[0]["subject"]
                    self.message = msg_template[0]["message"]

    def select_recipients(self, user_groups, recipients):
        """Select and populate recipients for the message based on user groups.

        Args:
            user_groups: A mapping of user group IDs to user IDs.
            recipients: A mapping of user IDs to recipient objects.
        """
        for groupid in self.groups:
            if groupid in user_groups:
                self.users += user_groups[groupid]
        for userid in self.users:
            if userid in recipients:
                recipient = copy.deepcopy(recipients[userid])
                if self.mediatypeid in recipient.sendto:
                    recipient.mediatype = True
                self.recipients.append(recipient)


class Recipient:
    """Represents a recipient of messages sent by Zabbix.

    Attributes:
        userid: The unique ID of the user.
        username: The username of the recipient.
        fullname: The full name of the recipient.
        type: The role type of the recipient within Zabbix (e.g., user, admin, super admin).
        groups: Set of user group IDs the recipient belongs to.
        has_right: Indicator for whether the recipient has permission to receive messages.
        permissions: Set of host group IDs for which the recipient has permissions.
        sendto: A dictionary of media type IDs to their respective recipient's medias.
    """

    def __init__(self, user):
        self.userid = user["userid"]
        self.username = user["username"]
        self.fullname = "{name} {surname}".format(**user).strip()
        self.type = user["role"]["type"]
        self.groups = set([g["usrgrpid"] for g in user["usrgrps"]])
        self.has_right = False
        self.permissions = set()
        self.sendto = {
            m["mediatypeid"]: m["sendto"] for m in user["medias"] if m["active"] == "0"
        }
        # Check if the user is a super admin (type 3)
        if self.type == "3":
            self.has_right = True
