# ===============================================
#     REQUÊTE DE PAIEMENT AU NIVEAU DES APIs
# ===============================================

import requests
import json 
import uuid
import datetime

# MOMO - MTN MONEY 
# --------------------------------

class MomoAPI:

    def __init__(self):
        pass

    def login(self, subscriptionkey):
        try:
            # Obtenir l'API User
            url = "https://sandbox.momodeveloper.mtn.com/v1_0/apiuser"
            user_id = str(uuid.uuid4())
            headers = {
                "X-Reference-Id": user_id,
                "Content-Type": "application/json",
                "Ocp-Apim-Subscription-Key": subscriptionkey
            }
            body = {
                "providerCallbackHost": "string"
            }
            req = requests.post(url, data=json.dumps(body), headers=headers)
            print("[+] Création de l'API User")
            if req.status_code != 201:
                return [0, "Impossible de créer l'API User"]

            # Création de l'API Key 
            url = f"https://sandbox.momodeveloper.mtn.com/v1_0/apiuser/{user_id}/apikey"
            headers = {
                "Ocp-Apim-Subscription-Key": subscriptionkey
            }
            req = requests.post(url, headers=headers)
            print("[+] Création de l'API KEY")
            if req.status_code != 201:
                return [0, "Impossible de créer l'API KEY"]
            apiKey = req.json()['apiKey']

            # Obtention des tokens 
            url = "https://sandbox.momodeveloper.mtn.com/collection/token/"
            headers = {
                "Ocp-Apim-Subscription-Key": subscriptionkey
            }
            req = requests.post(url, headers=headers, auth=(user_id, apiKey))
            print("[+] Obtention des tokens")
            if req.status_code != 200:
                return [0, "Impossible d'obtenir les tokens"]

            res = req.json()
            accessToken = res["access_token"]
            expiresIn = res["expires_in"]

            obj = {
                "userId": user_id,
                "subscriptionKey": subscriptionkey,
                "accessToken": accessToken,
                "expiresIn": expiresIn
            }
            return obj

        except:
            return 0

    def request_to_pay(self, userid, accesstoken, transactionId, amount, payer_phone, payer_message, payee_note):

        self.subscriptionkey_requesttopay = "ab523d4c23334d83a03d6cc3a5804361"
        currency = "EUR"
        requestToPayURL = "https://sandbox.momodeveloper.mtn.com/collection/v1_0/requesttopay"
        headers = {
            "Authorization": "Bearer " + accesstoken,
            "X-Reference-Id": userid,
            "X-Target-Environment": "sandbox",
            "Ocp-Apim-Subscription-Key": self.subscriptionkey_requesttopay
        }
        body = {
            "amount": amount,
            "currency": currency,
            "externalId": transactionId,
            "payer": {
                "partyIdType": "MSISDN",
                "partyId": payer_phone
            },
            "PayerMessage": payer_message,
            "PayeeNote": payee_note
        }
        try:
            req = requests.post(requestToPayURL, data=json.dumps(body), headers=headers)
        except:
            return [0, "Nous ne parvenons pas à accéder au site"]
        
        if req.status_code != 202:
            return [0, "Désolé l'opération ne peut pas être éffectué !"]

        return 1

    def getBasicUserInfo(self, access_token, phone_number):

        url = f"https://sandbox.momodeveloper.mtn.com/collection/v1_0/accountholder/msisdn/{phone_number}/basicuserinfo"
        headers = {
            "Authorization": "Bearer " + access_token,
            "X-Target-Environment": "sandbox",
            "Ocp-Apim-Subscription-Key": self.subscriptionkey_requesttopay
        }
        try:
            req = requests.get(url, headers=headers)
        except:
            return [0, "Nous ne parvenons pas à accéder au site"]
        if req.status_code != 200:
            return [0, "Désolé l'opération ne peut pas être éffectué !"]

        return req.json()

    def getAccountBalance(self, access_token, userid, phone_number):

        url = f"https://sandbox.momodeveloper.mtn.com/collection/v1_0/accountholder/msisdn/{phone_number}/basicuserinfo"
        headers = {
            "Authorization": "Bearer " + access_token,
            "X-Target-Environment": "sandbox",
            "Ocp-Apim-Subscription-Key": self.subscriptionkey_requesttopay
        }
        try:
            req = requests.get(url, headers=headers)
        except:
            return [0, "Nous ne parvenons pas à accéder au site"]
        if req.status_code != 200:
            return [0, "Désolé l'opération ne peut pas être éffectué !"]

        return req.json()

    def GenerateTransactionID(self):

        today = str(datetime.datetime.today()).replace("-", "")
        today = today.replace(":", "")
        today = today.replace(" ", "")
        today = today.replace(".", "_")
        id = "TID"+today
        return id

class OrangeMoneyAPI:

    def __init__(self):
        pass 

    def login(self):

        url = "https://api.orange.com/oauth/v3/token"
        authorization = "Basic MXpLTU01MnBMck44WDFHaUd0dWc5a3Q0enZJdEhQdkI6b1dkUENZWkdpWXNxNldQMg=="
        body = "grant_type=client_credentials"
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": authorization
        }
        req = requests.post(url, data=body, headers=headers)

        if req.status_code == 200:
            self.access_token = req.json()["access_token"]
            return 1

        return 0

    def requesttopay(self, transaction_id, amount):
        
        url = "https://api.orange.com/orange-money-webpay/dev/v1/webpayment"
        authorization = f"Bearer {self.access_token}"
        headers = {
            "Content-Type": "application/json",
            "Authorization": authorization,
        }
        body = {
            "merchant_key": "537f5491",
            "currency": "OUV",
            "order_id": transaction_id,
            "amount": int(amount),
            "return_url": "http://myvirtualshop.webnode.es",
            "cancel_url": "http://myvirtualshop.webnode.es/txncncld/",
            "notif_url": "http://www.merchant-example2.org/notif",
            "lang": "fr",
            "reference": "PrestaShop - INSTAPAY"
        }
        req = requests.post(url, data=json.dumps(body), headers=headers)
        if req.status_code == 201:
            return req.json()
        
        return 0

    def get_transaction_status(self, order_id, amount, pay_token):

        url = "https://api.orange.com/orange-money-webpay/dev/v1/transactionstatus"
        token = ""
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.access_token}",
        }
        body = {
            "order_id": order_id,
            "amount": amount,
            "pay_token": pay_token
        }
        req = requests(url, data=json.dumps(body), headers=headers)
        if req.status_code == 200:
            return req.json()

        return 0

    def GenerateTransactionID(self):

        today = str(datetime.datetime.today()).replace("-", "")
        today = today.replace(":", "")
        today = today.replace(" ", "")
        today = today.replace(".", "_")
        id = "TID"+today
        return id

"""
print("[+] Création de l'instance Orange Money")
OrangeMoney = OrangeMoneyAPI()
print("[+] Obtention du token ")
result = OrangeMoney.login()
if not result:
    print("Failed !")
    exit()

print("[+] Requête de paiement ")
transaction_id = OrangeMoney.GenerateTransactionID()
result = OrangeMoney.requesttopay(transaction_id, 20000)
print(result)

subscriptionkey = "ab523d4c23334d83a03d6cc3a5804361"
MTNMoney = MomoAPI()
result = MTNMoney.login(subscriptionkey)
print(result)

if result != list and result != 0:
    print(result)

    # Lançons la requête de paiement 
    access_token = result["accessToken"]
    userid = result["userId"]
    amount = "1000"
    payer_phone = "2250102030102"
    payer_message = "Un nouveau paiement"
    payee_note = "Paiement de Test !"
    result = MTNMoney.request_to_pay(access_token, userid, amount, payer_phone, payer_message, payee_note)
    if not result:
        print("Sorry !")
        exit()

    print("SUCCESS !")

    phone_number = "2250102030102"
    result = MTNMoney.getBasicUserInfo(access_token, phone_number)
    print(result)


MyMerchantKey =  537f5491



{
    "token_type": "Bearer",
    "access_token": "0kKpddWbSBzwndmDL4iTgjGSWcUx",
    "expires_in": 3600
}

#
#157803
"""