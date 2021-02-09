from annoying.fields import AutoOneToOneField
from django.contrib.auth import get_user_model
from django.db import models


class SocialUser(models.Model):
    user = AutoOneToOneField(get_user_model(), primary_key=True, on_delete=models.CASCADE)
    social_organisation = models.CharField(max_length=15)
    social_id = models.CharField(max_length=50)
    token = models.TextField(blank=True)
    refresh_token = models.TextField(blank=True)
