import email
from django.shortcuts import HttpResponse, get_object_or_404, get_list_or_404, redirect
from requests import request
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from api.models import APIAccess, PaymentMethod, Providers, Transactions, UserAccount

from api.serializers import APIAccessSerializer, ClientSerializer, MerchantSerializer, PaymentMethodSerializer, TransactionSerializer, BaseUserInfo
from api.models import UserAccount

from ressources.myscripts import CodeGenerator, SendMail, HashSecondAuthenticationCode
from ressources.payment_method import MomoAPI, OrangeMoneyAPI
import threading
import time
from datetime import datetime

# -------------------- MES FONCTIONS ------------------------- #

def CountDownDelete(email):
    pass
    #time.sleep(300)
    #user = get_object_or_404(UserAccount, email=email)
    #if user.temporary_code != None:
        #UserAccount.objects.get(email=email).delete()

def CountDown(email):
    pass
    #time.sleep(300)
    #user = get_object_or_404(UserAccount, email=email)
    #if user.temporary_code != None:
        #user.temporary_code = None
        #user.save()

def remove_fees(amount):

    money_to_send = int(amount) - int(amount)/100
    fees = int(amount) - money_to_send
    return (money_to_send, fees)

def GenerateTransactionID():

        today = str(datetime.today()).replace("-", "")
        today = today.replace(":", "")
        today = today.replace(" ", "")
        today = today.replace(".", "_")
        id = "TID"+today
        return id

# Create your views here.
def Index(request):

    content = "<h1> Welcome To INSTAPAY - API</h1>"
    return HttpResponse(content)


class DemoView(APIView):

    def get(self, request):
        return Response({"success": "Reponse à la requête GET"})

    def post(self, request):
        try:
            value = request.data['value']
        except:
            return Response({"errors": "Mauvaise requête"}, status=status.HTTP_400_BAD_REQUEST)
        
        obj = {"success": f"La valeur est : {value}"}
        return Response(obj, status=status.HTTP_200_OK)

    def put(self, request):
        try:
            value = request.data['value']
        except:
            return Response({"errors": "Mauvaise requête"}, status=status.HTTP_400_BAD_REQUEST)
        
        obj = {"success": f"La valeur est : {value}"}
        return Response(obj, status=status.HTTP_200_OK)
    
    def patch(self, request):
        try:
            value = request.data['value']
        except:
            return Response({"errors": "Mauvaise requête"}, status=status.HTTP_400_BAD_REQUEST)
        
        obj = {"success": f"La valeur est : {value}"}
        return Response(obj, status=status.HTTP_200_OK)

class SignUserView(APIView):
    
    def post(self, request, *args, **kargs):

        domain = "http://localhost:8000/api/v1/"
        #domain = "http://devinstapay.pythonanywhere.com/api/v1/"

        # Récupèration des données 
        try:
            print(request.data)
            user_status = request.data["status"]
            is_merchant = 0
            if user_status == "merchant":
                company_name = request.data["company_name"]
                area_activity = request.data["area_activity"]
                is_merchant = 1
            full_name = str(request.data["full_name"])
            email = str(request.data["email"])
            password = str(request.data["password"])
        except:
            return Response({"error": "Bad request ! please read documentation"}, status=status.HTTP_200_OK)

        if UserAccount.objects.filter(email=email).exists():
            obj = {"error": "Email already exist !"}
            return Response(obj, status=status.HTTP_406_NOT_ACCEPTABLE) #406 pas acceptable
        elif full_name == "" or full_name == None:
            obj = {"error": "Name field must not be empty !"}
            return Response(obj, status=status.HTTP_400_BAD_REQUEST) #400 Bad request
        elif user_status != "client" and user_status != "merchant":
            obj = {"error": "status must be client or merchant "}
            return Response(obj, status=status.HTTP_406_NOT_ACCEPTABLE)

        # Création du compte utilisateur
        temp_code = CodeGenerator()
        UserAccount.objects.create_user(
            email=email, 
            password=password
        )
        user = get_object_or_404(UserAccount, email=email)
        user.full_name = full_name
        user.temporary_code = temp_code
        user.status = user_status
        user.is_active = 0
        if is_merchant:
            user.company_name = company_name
            user.area_activity = area_activity
            user.balance = 0
        user.save()

        # Envoie du Mail de confirmation
        receiver = email
        subject = "Activation du compte"
        body = f"""
Hello {full_name},
Le Code De Confirmation Est Le Suivant : {temp_code}.

Vous Pouvez Aussi Cliquez Sur Le Lien Suivant Pour Activer Votre Compte
LE LIEN DE CONFIRMATION DE CONFIRMATION : {domain}users/active_my_account/{temp_code}/

Attention Ce Code N'est Valide Que Pendant 5 Min !
"""
        email_thread = threading.Thread(target=SendMail, args=(receiver, subject, body))
        email_thread.start()

        # Lancement du décompte
        th1 = threading.Thread(target=CountDownDelete, args=(email,))
        th1.start()

        # LA REPONSE
        obj = {
            "message": f"Email sent to {email}"
        }
        return Response(obj, status=status.HTTP_201_CREATED)

class ActiveMyAccountView(APIView):
    
    def get(self, request, temp_code):
        
        user = get_object_or_404(UserAccount, temporary_code=temp_code)
        user.temporary_code = None
        user.is_active = 1
        user.save()

        body = "<h1 style='color: green'>INSTAPAY</h1><p>Votre compte est maintenant activé</p>"
        #return redirect("https://www.google.com/")
        #return redirect("http://localhost/instapay_project_app/account_confirmation.html")
        return Response({"message": "Account activated !"}, status=status.HTTP_200_OK)

class SendCodeToResetPasswordView(APIView):

    def post(self, request):

        # Vérifions que l'utilisateur existe déja dans notre base de données
        user = get_object_or_404(UserAccount, email=request.data['email'])
        if not user.is_active:
            return Response({"error": "This account is not activate"}, status=status.HTTP_406_NOT_ACCEPTABLE)

        # Récupèration des données 
        # On va envoyé un mail à l'utilisateur contenant son nouveau mot de passe
        email_receiver = user.email
        subject = "Restauration Mot De Passe !"
        code_temp = CodeGenerator(size=10, numeric=0)
        body = f"""
Hello,
Code de Réinitialisation : {code_temp}
Attention Ce Code N'est Valide Que Pendant 5 Min !
"""
        reset_mdp_thread = threading.Thread(target=SendMail, args=(email_receiver, subject, body))
        reset_mdp_thread.start()

        # Mise à jour code de confirmation 
        user = get_object_or_404(UserAccount, email=request.data['email'])
        user.temporary_code = code_temp
        user.save()

        # On lance le décompte pour reset le code de confirmation 
        reset_confirmation_code_thread = threading.Thread(target=CountDown, args=(user.email,))
        reset_confirmation_code_thread.start()

        # La reponse 
        obj = {
            "message": f"Code to reset has been sent to {request.data['email']}"
        }
        return Response(obj, status=status.HTTP_200_OK) #200

class ResetPasswordUserView(APIView):
    
    def post(self, request, *args, **kargs):
        
        # Récupération des données (Code envoyés par mail, Nouveau Mot De Passe)
        try:
            email = request.data['email']
            code = request.data['reset_code']
            new_password = request.data['new_password']
        except:
            obj = {"message": "Email, reset_code and new_password are required !"}
            return Response(obj, status=status.HTTP_400_BAD_REQUEST)

        # Vérifions que l'utilisateur existe déja dans notre base de données
        user = get_object_or_404(UserAccount, email=email)
        if not user.is_active:
            return Response({"error": "This account is not activate"}, status=status.HTTP_406_NOT_ACCEPTABLE)

        # Vérification et Application des modifications
        if code == user.code_temp:
            user.set_password(new_password)
            user.double_authentication = 0
            user.double_authentication_code = None
            user.transaction_protection = 0
            user.transaction_protection_code = None
            user.save()

            obj = {
                "message": "Password Reset !"
            }
            return Response(obj, status=status.HTTP_200_OK)
        else:
            obj = {
                "error": "Impossible to reset user password !"
            }
            return Response(obj, status=status.HTTP_406_NOT_ACCEPTABLE) #406

class UserInformation(APIView):

    permission_classes = [IsAuthenticated]

    def get(self, request):
        
        user = get_object_or_404(UserAccount, email=request.user)
        if user.status == "client":
            serializer = ClientSerializer(user)
        else:
            serializer = MerchantSerializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):

        try:
            users_id = request.data["users_id"]
        except:
            return Response({"error": "Users_id is not defined !"}, status=status.HTTP_400_BAD_REQUEST)

        users_infos = []
        for user_id in users_id:
            userInfo = get_object_or_404(UserAccount, pk=user_id)
            obj = {
                "full_name": userInfo.full_name,
                "address": userInfo.email,
                "status": userInfo.status,
                "company_name": userInfo.company_name
            }
            users_infos.append(obj)

        return Response(userInfo)

class EditUserProfile(APIView):
    
    def put(self, request):

        # Vérification pour les users avec double authentification 
        user = get_object_or_404(UserAccount, email=request.user)
        if user.double_authentication:
            if not user.double_authentication_validated:
                obj = {"error": "access refused"}
                return Response(obj, status=status.HTTP_406_NOT_ACCEPTABLE)
        
        try:
            full_name = self.request.data["full_name"]
            email = self.request.data['email']
            phone_number = self.request.data['phone_number']
        except:
            obj = {"message": "full_name, email_user, phone_number are required"}
            return Response(obj, status=status.HTTP_400_BAD_REQUEST)

        user = get_object_or_404(UserAccount, email=request.user)

        if full_name:
            user.full_name = full_name
        
        if email:
            user.email = email
        
        if phone_number:
            user.phone_number = phone_number

        user.save()
        obj = {"message": "Successful update"}
        return Response(obj, status=status.HTTP_200_OK)

class SecurityUserView(APIView):

    permission_classes = [IsAuthenticated]

    def patch(self, request, *args, **kargs):

        # Vérification pour les users avec double authentification 
        user = get_object_or_404(UserAccount, email=request.user)
        if user.double_authentication:
            if not user.double_authentication_validated:
                obj = {"error": "access refused"}
                return Response(obj, status=status.HTTP_406_NOT_ACCEPTABLE)

        obj = {"message": "SUCCESS"}

        # On récupère les informations présente dans la requête puis on met à jour les donénes
        if self.request.GET.get('double_authentication'):
            double_authentication = self.request.GET.get('double_authentication')
            if int(double_authentication) == 1 or int(double_authentication) == 0:
                #return Response(obj, status=status.HTTP_200_OK)
                user.double_authentication = int(double_authentication)
                user.double_authentication_validated = 1
                user.save()
                obj["double_authentication"] = "SUCCESS UPDATE"
        
        if self.request.GET.get('email_alert'):
            email_alert = int(self.request.GET.get('email_alert'))
            if email_alert == 1 or email_alert == 0:
                user.alert_mail = 1
                user.save()
                obj["alert_mail"] = "Activated"

        if self.request.GET.get('transaction_protection'):
            account_protection = int(self.request.GET.get('transaction_protection'))
            
            try:
                account_protection_code = self.request.data['transaction_protection_code']
                useraccount = get_object_or_404(UserAccount, email=request.user)
            except:
                obj = {"error": "Transaction Protection code required "}
                return Response(obj, status=status.HTTP_400_BAD_REQUEST)

            if account_protection:
                if account_protection_code == "" or account_protection_code == None:
                    return Response({"error": "Transaction protection code cannot be null or empty"})

                account_protection_code_hash = HashSecondAuthenticationCode(account_protection_code)
                useraccount.transaction_protection = 1
                useraccount.transaction_protection_code = account_protection_code_hash
                useraccount.save()
                obj["account_protection_activation"] = "Activated"
            else:
                if useraccount.transaction_protection: # Si la protection du compte est activé alors on demande le code pin
                    # Avant de le désactiver
                    account_protection_code_hash = HashSecondAuthenticationCode(account_protection_code)
                    if account_protection_code_hash == useraccount.transaction_protection_code:
                        useraccount.transaction_protection = 0
                        useraccount.transaction_protection_code = None
                        useraccount.save()
                        obj["Transaction_Protection"] = "Deactivate" #Désactiver avec succès
                    else:
                        obj["Transaction_Protection"] = "Impossible to deactivate ! Transaction protection code is not correct"
                else:
                    obj["message"] = "SUCCESS UPDATE"
                    return Response(obj)
            
        return Response(obj, status=status.HTTP_200_OK)

class ChangePasswordUserView(APIView):

    permission_classes = [IsAuthenticated]

    def patch(self, request):

        # Vérification pour les users avec double authentification 
        user = get_object_or_404(UserAccount, email=request.user)
        if user.double_authentication:
            if not user.double_authentication_validated:
                obj = {"error": "access refused"}
                return Response(obj, status=status.HTTP_406_NOT_ACCEPTABLE)

        # Récupération des informations 
        try:
            old_password = request.data['old_password']
            new_password = request.data['new_password']
        except:
            obj = {"error": "old_password and new_password are required"}
            return Response(obj, status=status.HTTP_400_BAD_REQUEST)

        # Changement du mot de passe de l'utilisateur 
        queryset = get_object_or_404(UserAccount, email=request.user)
        queryset.set_password(new_password)
        queryset.save()

        # La reponse 
        obj = {
            "message": "Password changed"
        }
        return Response(obj, status=status.HTTP_200_OK) #200

class LoginForSecondAuthentication(APIView):

    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kargs):
        
        user = get_object_or_404(UserAccount, email=request.user)
        if user.double_authentication:
            code = CodeGenerator(size=8)
            receiver = user.email
            subject = "Double Authentification"
            body = f"""
Le Code Pour La Seconde Authentification Est : {code} 
"""
            user.double_authentication_code = HashSecondAuthenticationCode(code)
            user.save()
            th1 = threading.Thread(target=SendMail, args=(receiver, subject, body))
            th1.start()

            # Lancement du décompte
            th2 = threading.Thread(target=CountDown, args=(user.email,))
            th2.start()

            obj = {"message": f"Second authentication code sent to {user.email}"}
            return Response(obj, status=status.HTTP_200_OK)
        else:
            obj = {"message": "Failed"}
            return Response(obj, status=status.HTTP_400_BAD_REQUEST)

    def post(self, request, *args, **kargs):
        
        # Récupèration du code pour la double authentification et le user
        user = get_object_or_404(UserAccount, email=request.user)
        try:
            code = request.data['second_authentication_code']
        except:
            return Response({"error": "Bad request, read documentation please"}, status=status.HTTP_400_BAD_REQUEST)
        code = HashSecondAuthenticationCode(code)

        if user.double_authentication == 1 and user.double_authentication_code == code:
            user.double_authentication_validated = 1
            user.save()
            obj = {"message": "Double authentification success"}
            return Response(obj, status=status.HTTP_200_OK)
        else:
            obj = {"error": "double authentication failed"}
            return Response(obj, status=status.HTTP_401_UNAUTHORIZED)

class LogoutUserView(APIView):

    permission_classes = [IsAuthenticated]

    def post(self, request):

        # Vérification pour les users avec double authentification 
        user = get_object_or_404(UserAccount, email=request.user)
        if user.double_authentication:
            if not user.double_authentication_validated:
                obj = {"error": "access refused"}
                return Response(obj, status=status.HTTP_406_NOT_ACCEPTABLE)

        try:
            refresh_token = request.data['refresh']
        except:
            obj = {"error": "Refresh token required !"}
            return Response(obj, status=status.HTTP_400_BAD_REQUEST)

        try:
            RefreshToken(refresh_token).blacklist()
        except TokenError:
            raise ValueError("Token already expired !")

        user.double_authentication_validated = 0
        if user.double_authentication:
            user.double_authentication_code = HashSecondAuthenticationCode("empty")
            user.last_login = datetime.today()
            user.save()
        
        obj = {"message": "User logout"}
        return Response(obj, status=status.HTTP_200_OK)

# LES METHODES DE PAIEMENT #
class AddPaymentMethod(APIView):

    permission_classes = [IsAuthenticated]

    def get(self, request):

        # Vérification pour les users avec double authentification 
        user = get_object_or_404(UserAccount, email=request.user)
        if user.double_authentication:
            if not user.double_authentication_validated:
                obj = {"error": "access refused"}
                return Response(obj, status=status.HTTP_406_NOT_ACCEPTABLE)
        
        queryset = PaymentMethod.objects.filter(owner=request.user)
        serializer = PaymentMethodSerializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    def post(self, request):

        # Vérification pour les users avec double authentification 
        user = get_object_or_404(UserAccount, email=request.user)
        if user.double_authentication:
            if not user.double_authentication_validated:
                obj = {"error": "access refused"}
                return Response(obj, status=status.HTTP_406_NOT_ACCEPTABLE)

        try:
            provider_name = request.data["provider"]
            phone_number = request.data["phone_number"]
        except:
            obj = {
                "error": "provider and phone number are required !"
            }
            return Response(obj, status=status.HTTP_400_BAD_REQUEST)

        provider = get_object_or_404(Providers, name=provider_name)
        PaymentMethod.objects.create(owner=request.user, address=phone_number, provider=provider, state=1)
        return Response({"message": "SUCCESS !"}, status=status.HTTP_200_OK)

class ActivatePaymentMethod(APIView):
    pass 

class TransactionStatus(APIView):

    permission_classes = [IsAuthenticated]
    
    def get(self, request, transaction_id):

        queryset = get_object_or_404(Transactions, id=transaction_id)
        serializer = TransactionSerializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class TransactionList(APIView):

    permission_classes = [IsAuthenticated]
    
    def get(self, request):

        payer = Transactions.objects.filter(payer=request.user)
        payee = Transactions.objects.filter(payee=request.user)
        serializer_payer = TransactionSerializer(payer, many=True)        
        serializer_payee = TransactionSerializer(payee, many=True)
        obj = {
            "payer": serializer_payer.data,
            "payee": serializer_payee.data
        }
        return Response(obj, status=status.HTTP_200_OK)

class TransactionForClient(APIView):
    
    permission_classes = [IsAuthenticated]

    def post(self, request):
        
        try:
            provider_name = str(request.data["provider"])
            payee = request.data["payee"]
            amount = int(request.data["amount"])
            note = request.data["note"]
            transaction_protection_code = request.data["transaction_protection_code"]
        except:
            return Response({"error": "provider, payee, amount are required !"}, status=status.HTTP_400_BAD_REQUEST)

        instapay = get_object_or_404(UserAccount, email="master@instapay.com")
        payer = get_object_or_404(UserAccount, email=request.user)
        payee = get_object_or_404(UserAccount, email=payee)
        provider = get_object_or_404(Providers, name=provider_name)

        if payer.status == "merchant":
            return Response({"error": "Merchant cannot do this !"})

        if str(payer.email) == str(payee) and provider_name == "INSTAPAY":
            return Response({"error": "You cannot send money to yourself !"}, status=status.HTTP_406_NOT_ACCEPTABLE)

        # On applique les frais
        apply_fees = remove_fees(amount)
        money_to_send = apply_fees[0]
        our_money = apply_fees[1]

        if provider_name == "INSTAPAY":

            #Todo payment with instapay account 
            payer.balance -= amount
            payee.balance += money_to_send
            instapay.balance += our_money
            payer.save()
            payee.save()
            instapay.save()

            transaction_id = GenerateTransactionID()
            Transactions.objects.create(
                id=transaction_id, 
                payer=payer, 
                payer_address=payer.email,
                note=note,
                payee=payee, 
                amount=money_to_send, 
                provider=provider, 
                status=1
                )
            serializer = BaseUserInfo(payee)
            obj = {
                "message": "SUCCESS",
                "ID": transaction_id,
                "amount": money_to_send,
                "payee": serializer.data,
                "datetime": datetime.today()
            }
            return Response(obj, status=status.HTTP_200_OK)

        elif provider_name == "MTN":

            # Pay With MTN
            try:
                payer_address = PaymentMethod.objects.get(owner=payer, provider=provider).address
            except:
                return Response({"error": "No payment method saved for this provider !"})

            transaction_id = GenerateTransactionID()
            subscriptionkey = "ab523d4c23334d83a03d6cc3a5804361"
            MTNMoney = MomoAPI()
            result = MTNMoney.login(subscriptionkey)
            if result != list and result != 0:
                # Lançons la requête de paiement 
                access_token = result["accessToken"]
                userid = result["userId"]
                amount = str(money_to_send)
                payer_phone = payer_address
                payer_message = "Payer votre marchand avec INSTAPAY"
                payee_note = note
                result = MTNMoney.request_to_pay(access_token, userid, transaction_id, amount, payer_phone, payer_message, payee_note)
                if not result:
                    print("Sorry !")
                    return Response({"error": "Sorry impossible to pay with MTN right now ! Please retry later"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

                Transactions.objects.create(
                    id=transaction_id, 
                    payer=payer, 
                    payer_address=payer_address,
                    note=note,
                    payee=payee, 
                    amount=money_to_send, 
                    provider=provider, 
                    status=1
                )
                serializer = BaseUserInfo(payee)
                obj = {
                    "message": "SUCCESS",
                    "ID": transaction_id,
                    "payer_address": payer_address,
                    "amount": money_to_send,
                    "payee": serializer.data,
                    "datetime": datetime.today()
                }
                instapay.balance += our_money
                instapay.save()
                return Response(obj, status=status.HTTP_200_OK)
            else:
                return Response({"error": "Sorry impossible to pay with MTN right now ! Please retry later"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        elif provider_name == "ORANGE":
            # Pay with ORANGE

            try:
                payer_address = PaymentMethod.objects.get(owner=payer, provider=provider).address
            except:
                return Response({"error": "No payment method saved for this provider !"})

            OrangeMoney = OrangeMoneyAPI()
            result = OrangeMoney.login()
            if not result:
                return Response({"error": "Sorry impossible to pay with ORANGE right now ! Please retry later"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            transaction_id = OrangeMoney.GenerateTransactionID()
            try:
                result = OrangeMoney.requesttopay(transaction_id, money_to_send)
                print(result)
                print("-------------------------------------")
                go_to_pay = result["payment_url"]
                print(go_to_pay)
                Transactions.objects.create(
                    id=transaction_id, 
                    payer=payer, 
                    payer_address=payer_address,
                    note=note,
                    payee=payee, 
                    amount=money_to_send, 
                    provider=provider, 
                    status=1
                )
                serializer = BaseUserInfo(payee)
                obj = {
                    "message": "WAIT TO CONFIRMATION",
                    "ID": transaction_id,
                    "payer_address": payer_address,
                    "amount": money_to_send,
                    "payee":serializer.data,
                    "go_to_url": go_to_pay,
                    "datetime": datetime.today()
                }
                instapay.balance += our_money
                instapay.save()
                return Response(obj, status=status.HTTP_200_OK)
            except:
                return Response({"error": "Sorry impossible to pay with ORANGE right now ! Please retry later"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        elif provider_name == "MOOV": 
            # Pay with MOOV
            pass
        else:
            return Response("failed !")
                

class TransactionForMerchant(APIView):

    permission_classes = [IsAuthenticated]
    
    def post(self, request):

        merchant = get_object_or_404(UserAccount, email=request.user)

        #Récupèration des données de la transaction
        try:
            provider_name = str(request.data["provider"])
            payer_address = str(request.data["payer_address"])
            amount = int(request.data["amount"])
            code = request.data["code"]
        except:
            return Response({"error": "provider, payer_address, amount and code are required !"}, status=status.HTTP_400_BAD_REQUEST)
        
        instapay = get_object_or_404(UserAccount, email="master@instapay.com")
        provider = get_object_or_404(Providers, name=provider_name)

        queryset = PaymentMethod.objects.all()
        if len(queryset) > 0:
            for elt in queryset:
                print(elt)
                if elt.address == payer_address:
                    payer = get_object_or_404(UserAccount, pk=elt.owner)
                    break
                else:
                    payer = get_object_or_404(UserAccount, email="noinstapayuser@yopmail.com")
        else:
            payer = get_object_or_404(UserAccount, email="noinstapayuser@yopmail.com")

        if str(payer_address) == str(merchant.email):
            return Response({"error": "You can not send money to yourself !"}, status=status.HTTP_406_NOT_ACCEPTABLE)

        # On applique les frais
        apply_fees = remove_fees(amount)
        money_to_send = apply_fees[0]
        our_money = apply_fees[1]

        if provider_name == "INSTAPAY":

            #Todo payment with instapay account
            payer = get_object_or_404(UserAccount, email=payer_address)
            if code == payer.temporary_code:
                payer = get_object_or_404(UserAccount, email=payer_address) 
                payer.temporary_code = None
                payer.balance -= amount
                merchant.balance += money_to_send
                instapay.balance += our_money
                payer.save()
                merchant.save()
                instapay.save()

                transaction_id = GenerateTransactionID()
                Transactions.objects.create(
                    id=transaction_id, 
                    payer=payer, 
                    payer_address=payer.email,
                    note="Test Instapay",
                    payee=merchant, 
                    amount=money_to_send, 
                    provider=provider, 
                    status=1
                    )
                serializer = BaseUserInfo(merchant)
                obj = {
                    "message": "SUCCESS",
                    "ID": transaction_id,
                    "amount": money_to_send,
                    "payee": serializer.data,
                    "datetime": datetime.today()
                }
                return Response(obj, status=status.HTTP_200_OK)

            else:
                payer.temporary_code = None
                payer.save()
                return Response({"error": "Code to execute this transaction is not valid"})

        elif provider_name == "MTN":

            #try:
            transaction_id = GenerateTransactionID()
            subscriptionkey = "ab523d4c23334d83a03d6cc3a5804361"
            MTNMoney = MomoAPI()
            result = MTNMoney.login(subscriptionkey)
            if result != list and result != 0:
                # Lançons la requête de paiement 
                access_token = result["accessToken"]
                userid = result["userId"]
                amount = str(money_to_send)
                payer_phone = payer_address
                payer_message = "Simple Payment"
                payee_note = "Pay Your Merchant With Instapay API"
                result = MTNMoney.request_to_pay(access_token, userid, transaction_id, amount, payer_phone, payer_message, payee_note)
                if not result:
                    print("Sorry !")
                    return Response({"error": "Sorry impossible to pay with MTN right now ! Please retry later"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

                transaction_id = GenerateTransactionID()
                Transactions.objects.create(
                    id=transaction_id, 
                    payer=payer, 
                    payer_address=payer.email,
                    note="Test Instapay - MTN",
                    payee=merchant, 
                    amount=money_to_send, 
                    provider=provider, 
                    status=1
                )
                serializer = BaseUserInfo(merchant)
                obj = {
                    "message": "SUCCESS",
                    "ID": transaction_id,
                    "amount": money_to_send,
                    "payee": serializer.data,
                    "datetime": datetime.today()
                }
                merchant.balance += money_to_send
                instapay.balance += our_money
                instapay.save()
                merchant.save()
                return Response(obj, status=status.HTTP_200_OK)
            #except:
                #return Response({"error": "Sorry impossible to pay with MTN right now ! Please retry later"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        elif provider_name == "ORANGE":

            try:
                OrangeMoney = OrangeMoneyAPI()
                result = OrangeMoney.login()
                if not result:
                    return Response({"error": "Sorry impossible to pay with ORANGE right now ! Please retry later"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

                transaction_id = OrangeMoney.GenerateTransactionID()        
                transaction_id = GenerateTransactionID()
                Transactions.objects.create(
                    id=transaction_id, 
                    payer=payer, 
                    payer_address=payer.email,
                    note="Test Instapay - MTN",
                    payee=merchant, 
                    amount=money_to_send, 
                    provider=provider, 
                    status=1
                    )
                serializer = BaseUserInfo(merchant)
                obj = {
                    "message": "SUCCESS",
                    "ID": transaction_id,
                    "amount": money_to_send,
                    "payee": serializer.data,
                    "datetime": datetime.today()
                }
                merchant.balance += money_to_send
                instapay.balance += our_money
                instapay.save()
                merchant.save()
                return Response(obj, status=status.HTTP_200_OK)
            except:
                return Response({"error": "Sorry impossible to pay with ORANGE right now ! Please retry later"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            pass

class TransactionForMerchantWithoutToken(APIView):
    
    def post(self, request):

        try:
            apiUser = request.data["apiUser"]
            apiKey = request.data["apiKey"]
        except:
            return Response({"error": "Bad request ! Read documentation please !"})

        merchant = get_object_or_404(APIAccess, apiKey=apiKey, apiUser=apiUser)
        payee = get_object_or_404(UserAccount, email=merchant.owner)

        #Récupèration des données de la transaction
        try:
            provider_name = str(request.data["provider"])
            payer_address = str(request.data["payer_address"])
            amount = int(request.data["amount"])
            code = request.data["code"]
        except:
            return Response({"error": "provider, payer_address, amount and code are required !"}, status=status.HTTP_400_BAD_REQUEST)
        
        instapay = get_object_or_404(UserAccount, email="master@instapay.com")
        provider = get_object_or_404(Providers, name=provider_name)

        queryset = PaymentMethod.objects.all()
        if len(queryset) > 0:
            for elt in queryset:
                print(elt)
                if elt.address == payer_address:
                    payer = get_object_or_404(UserAccount, pk=elt.owner)
                    break
                else:
                    payer = get_object_or_404(UserAccount, email="noinstapayuser@yopmail.com")
        else:
            payer = get_object_or_404(UserAccount, email="noinstapayuser@yopmail.com")

        if str(payer_address) == str(payee.email):
            return Response({"error": "You can not send money to yourself !"}, status=status.HTTP_406_NOT_ACCEPTABLE)

        # On applique les frais
        apply_fees = remove_fees(amount)
        money_to_send = apply_fees[0]
        our_money = apply_fees[1]

        if provider_name == "INSTAPAY":

            #Todo payment with instapay account
            payer = get_object_or_404(UserAccount, email=payer_address)
            if code == payer.temporary_code:
                payer = get_object_or_404(UserAccount, email=payer_address) 
                payer.temporary_code = None
                payer.balance -= amount
                payee.balance += money_to_send
                instapay.balance += our_money
                payer.save()
                payee.save()
                instapay.save()

                transaction_id = GenerateTransactionID()
                Transactions.objects.create(
                    id=transaction_id, 
                    payer=1, 
                    payer_address=payer.email,
                    note="Test Instapay",
                    payee=merchant, 
                    amount=money_to_send, 
                    provider=provider, 
                    status=1
                    )
                serializer = BaseUserInfo(merchant)
                obj = {
                    "message": "SUCCESS",
                    "ID": transaction_id,
                    "amount": money_to_send,
                    "payee": serializer.data,
                    "datetime": datetime.today()
                }
                return Response(obj, status=status.HTTP_200_OK)

            else:
                payer.temporary_code = None
                payer.save()
                return Response({"error": "Code to execute this transaction is not valid"}, status=401)

        elif provider_name == "MTN":

            try:
                transaction_id = GenerateTransactionID()
                subscriptionkey = "ab523d4c23334d83a03d6cc3a5804361"
                MTNMoney = MomoAPI()
                result = MTNMoney.login(subscriptionkey)
                if result != list and result != 0:
                    # Lançons la requête de paiement 
                    access_token = result["accessToken"]
                    userid = result["userId"]
                    amount = str(money_to_send)
                    payer_phone = payer_address
                    payer_message = "Simple Payment"
                    payee_note = "Pay Your Merchant With Instapay API"
                    result = MTNMoney.request_to_pay(access_token, userid, transaction_id, amount, payer_phone, payer_message, payee_note)
                    if not result:
                        print("Sorry !")
                        return Response({"error": "Sorry impossible to pay with MTN right now ! Please retry later"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

                    transaction_id = GenerateTransactionID()
                    Transactions.objects.create(
                        id=transaction_id, 
                        payer=payer, 
                        payer_address=payer.email,
                        note="Test Instapay - MTN",
                        payee=payee, 
                        amount=money_to_send, 
                        provider=provider, 
                        status=1
                    )
                    serializer = BaseUserInfo(payee)
                    obj = {
                        "message": "SUCCESS",
                        "ID": transaction_id,
                        "amount": money_to_send,
                        "payee": serializer.data,
                        "datetime": datetime.today()
                    }
                    payee.balance += money_to_send
                    instapay.balance += our_money
                    instapay.save()
                    payee.save()
                    return Response(obj, status=status.HTTP_200_OK)
            except:
                return Response({"error": "Sorry impossible to pay with MTN right now ! Please retry later"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        elif provider_name == "ORANGE":

            try:
                OrangeMoney = OrangeMoneyAPI()
                result = OrangeMoney.login()
                if not result:
                    return Response({"error": "Sorry impossible to pay with ORANGE right now ! Please retry later"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

                transaction_id = OrangeMoney.GenerateTransactionID()        
                transaction_id = GenerateTransactionID()
                Transactions.objects.create(
                    id=transaction_id, 
                    payer=payer, 
                    payer_address=payer.email,
                    note="Test Instapay - MTN",
                    payee=payee, 
                    amount=money_to_send, 
                    provider=provider, 
                    status=1
                    )
                serializer = BaseUserInfo(payee)
                obj = {
                    "message": "SUCCESS",
                    "ID": transaction_id,
                    "amount": money_to_send,
                    "payee": serializer.data,
                    "datetime": datetime.today()
                }
                payee.balance += money_to_send
                instapay.balance += our_money
                instapay.save()
                payee.save()
                return Response(obj, status=status.HTTP_200_OK)
            except:
                return Response({"error": "Sorry impossible to pay with ORANGE right now ! Please retry later"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response({"error": "This provider is not supported !"}, status=400)


class GenerateAPIKey(APIView):

    permission_classes = [IsAuthenticated]

    def get(self, request):
        
        user = get_object_or_404(UserAccount, email=request.user)
        if user.status != "merchant":
            return Response({"error": "You are not merchant. you cannot get APIKey"}, status=status.HTTP_401_UNAUTHORIZED)
        temp_code = CodeGenerator(size=8)
        receiver = user.email
        subject = "Developer Key For API"
        body = f"""
Hello,
Code pour la création de l'APIUser et l'APIKey : {temp_code}
Attention Ce Code N'est Valide Que Pendant 5 Min !
""" 
        user.temporary_code = temp_code
        user.save()
        th1 = threading.Thread(target=SendMail, args=(receiver, subject, body))
        th1.start()
        # Lancement du décompte
        th1 = threading.Thread(target=CountDown, args=(user.email,))
        th1.start()

        return Response({"message": f"Confirmation code sent to {user.email}"}, status=status.HTTP_200_OK)

    def post(self, request):

        try:
          temp_code = request.data["code"]  
        except:
            return Response({"error": "Bad request. Please read documentation !"})

        merchant = get_object_or_404(UserAccount, email=request.user)
        if merchant.temporary_code == temp_code:
            apiUser = CodeGenerator(size=30, numeric=0)
            apiKey = CodeGenerator(size=40, numeric=0)
            APIAccess.objects.create(apiUser=apiUser, apiKey=apiKey, owner=merchant)
            return Response({"message": "SUCCESS"}, status=status.HTTP_200_OK)

class GetDeveloperAPIKey(APIView):

    permission_classes = [IsAuthenticated]

    def get(self, request):

        user = get_object_or_404(UserAccount, email=request.user)
        developer_api_access = get_object_or_404(APIAccess, owner=user)
        serializer = APIAccessSerializer(developer_api_access)
        return Response(serializer.data)


class GenerateTemporaryCode(APIView):

    permission_classes = [IsAuthenticated]

    def get(self, request):
        
        temp_code = CodeGenerator()
        user = get_object_or_404(UserAccount, email=request.user)
        user.temporary_code = temp_code
        user.save()

        # Lancement du décompte
        th1 = threading.Thread(target=CountDown, args=(user.email,))
        th1.start()

        return Response({"code": str(temp_code)}, status=status.HTTP_200_OK)