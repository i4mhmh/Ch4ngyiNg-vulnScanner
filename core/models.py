from django.db import models

# Create your models here.
class Urls(models.Model):
    urls = models.CharField(max_length=1000)