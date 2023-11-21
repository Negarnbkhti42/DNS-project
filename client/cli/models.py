from django.db import models
from fernet_fields import EncryptedTextField, EncryptedCharField


class User(models.Model):
    username = models.CharField(max_length=50, primary_key=True)
    online = models.BooleanField(default=False)
    password = EncryptedCharField(max_length=50, null=True, default=None)
    public_key = models.CharField(max_length=512)
    private_key = EncryptedTextField(null=True, default=None)
    session_key = EncryptedTextField(null=True, default=None)
    is_me = models.BooleanField(default=False)
    diffie_hellman_public_parameters_text = models.TextField(null=True, default=None)
    diffie_hellman_public_key_text = models.TextField(null=True, default=None)


class Group(models.Model):
    group_name = models.CharField(max_length=50, primary_key=True)
    admin = models.ForeignKey(User, on_delete=models.CASCADE, related_name='groups_administered')
    session_key = EncryptedTextField(null=True)
    members = models.ManyToManyField(User, related_name='groups_joined')


class DiffieHellman(models.Model):
    diffie_hellman_private_parameters_text = EncryptedTextField()
    diffie_hellman_public_parameters_text = models.TextField()
    diffie_hellman_public_key_text = models.TextField()


class SessionKey(models.Model):
    diffie_hellman = models.ForeignKey(DiffieHellman, on_delete=models.CASCADE)
    session_key = EncryptedTextField(null=True, default=None)
    group = models.ForeignKey(Group, on_delete=models.CASCADE, null=True, default=None)
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, default=None)


class Message(models.Model):
    message = EncryptedTextField()
    signature = models.TextField()
    sender = models.ForeignKey(User, on_delete=models.CASCADE)
    public_key = models.TextField()
    datetime = models.DateTimeField()
    group = models.ForeignKey(Group, on_delete=models.CASCADE, null=True, default=None)
