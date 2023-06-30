from django.db import models
from fernet_fields import EncryptedCharField


class User(models.Model):
    username = models.CharField(max_length=50, primary_key=True)
    password = EncryptedCharField(max_length=50)
    public_key = models.TextField(null=True)
    online = models.BooleanField()
    logged_in = models.BooleanField()
    # if public key or following parameters are null don't show these users
    diffie_hellman_public_parameters_text = models.TextField(null=True, default=None)
    diffie_hellman_public_key_text = models.TextField(null=True, default=None)


class Group(models.Model):
    group_name = models.CharField(max_length=50, primary_key=True)
    admin = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="groups_administered"
    )
    members = models.ManyToManyField(User, related_name="groups_joined")


class PendingMessage(models.Model):
    encrypted_message = models.TextField()
    sender = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="pending_messages_sent"
    )
    receiver = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        null=True,
        default=None,
        related_name="pending_messages_received",
    )
    group = models.ForeignKey(Group, on_delete=models.CASCADE, null=True, default=None)


class PendingNewSessionMessage(PendingMessage):
    diffie_hellman_public_parameters_text = models.TextField()
    sender_diffie_hellman_public_key_text = models.TextField()
    receiver_diffie_hellman_public_key_text = models.TextField()


class PendingAction(models.Model):
    sender = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="pending_actions_sent"
    )
    receiver = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="pending_actions_received"
    )


class NewGroupSession(PendingAction):
    group = models.ForeignKey(Group, on_delete=models.CASCADE)
    encrypted_session_key = models.TextField()
    diffie_hellman_public_parameters_text = models.TextField()
    sender_diffie_hellman_public_key_text = models.TextField()
    receiver_diffie_hellman_public_key_text = models.TextField()
