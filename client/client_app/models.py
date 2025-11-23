#done by Omar

from django.db import models
from django.db.models.signals import post_save
from django.dispatch import receiver
# Create your models here.
from django.contrib.auth.models import User
from django.db import models

class Profile(models.Model):
    ROLE_CHOICES = (
        ('admin', 'Admin'),
        ('user', 'User'),
    )
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='user')

    def __str__(self):
        return f"{self.user.username} - {self.role}"
@receiver(post_save, sender=User)
def create_profile(sender, instance, created, **kwargs):
    if created:
        Profile.objects.create(user=instance)