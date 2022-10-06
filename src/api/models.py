from enum import unique
from django.db import models
from django.contrib.auth.base_user import AbstractBaseUser, BaseUserManager

# Create your models here.
class MyUserManager(BaseUserManager):

    def create_user(self, email, password):
        if not email or not password:
            raise ValueError("Email, Password are required !")

        user = self.model(
            email = self.normalize_email(email)
        )
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, email, password):
        user = self.create_user(email=email, password=password)
        user.is_admin = True
        user.is_stuff = True 
        user.save()
        return user

class UserAccount(AbstractBaseUser):
    
    full_name = models.CharField(max_length=100, blank=False, null=False)
    email = models.EmailField(unique=True, max_length=255, blank=False)
    # Password and Last_login
    status = models.CharField(default="client", max_length=50)
    temporary_code = models.CharField(max_length=6, null=True)
    balance = models.FloatField(default=1000000)
    date_created = models.DateTimeField(auto_now_add=True)
    # Security 
    double_authentication = models.BooleanField(default=False)
    double_authentication_code = models.CharField(max_length=6, null=True)
    double_authentication_validated = models.BooleanField(default=False, null=True)
    transaction_protection = models.BooleanField(default=False)
    transaction_protection_code = models.CharField(max_length=6, null=True)
    alert_mail = models.BooleanField(default=False)
    # More Info To Relative to Merchant
    company_name = models.CharField(max_length=100, null=True)
    area_activity = models.CharField(max_length=100, null=True)
    phone_number = models.CharField(max_length=15, null=True)

    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_admin = models.BooleanField(default=False)

    # Les informations personnelle

    USERNAME_FIELD = "email"
    objects = MyUserManager()

    def has_perm(self, perm, obj=None):
        return True 

    def has_module_perms(self, app_label):
        return True

class APIAccess(models.Model):

    apiUser = models.CharField(max_length=100, null=False)
    apiKey = models.CharField(max_length=100)
    owner = models.ForeignKey(UserAccount, on_delete=models.CASCADE, related_name="apiAccessOwner")
    date_added = models.DateTimeField(auto_now_add=True)

class Providers(models.Model):

    name = models.CharField(max_length=100, unique=True, null=False, blank=False)
    date_added = models.DateTimeField(auto_now_add=True)
    state = models.BooleanField(default=False)

class Transactions(models.Model):

    id = models.CharField(max_length=50, null=False, unique=True, primary_key=True)
    payer = models.ForeignKey(UserAccount, on_delete=models.CASCADE, related_name="payer")
    payer_address = models.CharField(max_length=100, null=True)
    note = models.CharField(max_length=255, null=True)
    payee = models.ForeignKey(UserAccount, on_delete=models.CASCADE, related_name="payee")
    amount = models.FloatField(default=0)
    provider = models.ForeignKey(Providers, on_delete=models.CASCADE, related_name="provider_from_transaction")
    datetime = models.DateTimeField(auto_now_add=True)
    status = models.BooleanField(blank=False, null=False, default=2)

class PaymentMethod(models.Model):

    owner = models.ForeignKey(UserAccount, on_delete=models.CASCADE, related_name="owner")
    address = models.CharField(max_length=100, null=False, unique=True)
    provider = models.ForeignKey(Providers, on_delete=models.CASCADE, related_name="provider_from_paymentmethod")
    state = models.BooleanField(default=0)