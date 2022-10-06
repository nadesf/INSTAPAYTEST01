from dataclasses import field
from rest_framework.serializers import ModelSerializer, Serializer, SerializerMethodField
from api.models import APIAccess, UserAccount, Transactions, PaymentMethod, Providers


class BaseUserInfo(ModelSerializer):

    class Meta:
        model = UserAccount
        fields = ["full_name", "email", "company_name", "status"]

class ClientSerializer(ModelSerializer):

    class Meta:
        model = UserAccount 
        fields = ["full_name", "email", "status", "balance", "is_active", "double_authentication", "transaction_protection"]

class  MerchantSerializer(ModelSerializer):

    class Meta:
        model = UserAccount 
        fields = ["full_name", "email", "status", "balance", "is_active", "company_name", "area_activity", "double_authentication", "transaction_protection"]

class TransactionSerializer(ModelSerializer):

    class Meta:
        model = Transactions
        fields = ["id", "payee", "amount", "datetime", "status"]

class ProviderSerializer(ModelSerializer):

    class Meta:
        model = Providers
        fields = '__all__'

class APIAccessSerializer(ModelSerializer):

    class Meta:
        model = APIAccess
        fields = '__all__'

class PaymentMethodSerializer(ModelSerializer):

    class Meta:
        model = PaymentMethod
        fields = '__all__'