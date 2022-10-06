from django.urls import path, include
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from api.views import AddPaymentMethod, GenerateAPIKey, Index, SignUserView, ActiveMyAccountView, TransactionForClient, TransactionList, UserInformation, TransactionForMerchantWithoutToken, LoginForSecondAuthentication
from api.views import EditUserProfile, ChangePasswordUserView, LogoutUserView, SendCodeToResetPasswordView, ResetPasswordUserView, GenerateTemporaryCode, TransactionForMerchant, SecurityUserView, TransactionStatus, GetDeveloperAPIKey

urlpatterns = [
    path("", Index, name="index"),
    
    path("users/signup/", SignUserView.as_view()), # Inscrition
    path("users/active_my_account/<str:temp_code>/", ActiveMyAccountView.as_view()), # Confirmation
    path("users/ask_reset_password/", SendCodeToResetPasswordView.as_view()),
    path("users/reset_password/", ResetPasswordUserView.as_view()),
    path("users/login/", TokenObtainPairView.as_view()), # Connexion
    path("users/loginSecondAuthentication/", LoginForSecondAuthentication.as_view()),
    path("users/logout/", LogoutUserView.as_view()),
    path("users/tokenrefresh/", TokenRefreshView.as_view()), # Rafraichissement de token
    path("users/", UserInformation.as_view()),
    path("users/edit_profile/", EditUserProfile.as_view()),
    path("users/change_password/", ChangePasswordUserView.as_view()),
    path("users/securityoption/", SecurityUserView.as_view()),
    path("users/transactions/", TransactionList.as_view()),
    path("users/transactionsFromClient/", TransactionForClient.as_view()),
    path("users/transactionsFromMerchant/", TransactionForMerchant.as_view()),
    path("users/transactionsFromDeveloper/", TransactionForMerchantWithoutToken.as_view()),
    path("users/transaction/<str:transaction_id>/status/", TransactionStatus.as_view()),
    path("users/addPaymentMethod/", AddPaymentMethod.as_view()),
    path("users/generateAPIKey/", GenerateAPIKey.as_view()),
    path("users/getDeveloperAPIKey/", GetDeveloperAPIKey.as_view()),
    path("users/getTemporaryCode/", GenerateTemporaryCode.as_view())
]

"""
{
    "refresh": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbl90eXBlIjoicmVmcmVzaCIsImV4cCI6MTY2NTA3MjQxMCwianRpIjoiYzc1ZTlkYWIzN2EwNGJiNWI0NDI0OWY5NzZkMTM0MjEiLCJ1c2VyX2lkIjo2fQ.mOZiSidVS6YPJ8mRL0drLB2SVxDXVg3-tnBgFC7p5Xo",
    "access": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbl90eXBlIjoiYWNjZXNzIiwiZXhwIjoxNjY1MDIyMDEwLCJqdGkiOiJhMDUwNjVjMTQyYjY0YWJjYTBlNjQ5NDdiZTEzNDY1ZiIsInVzZXJfaWQiOjZ9.KRx5dyS_cBg2PkjcoFm5VRMEshXC-mW7omLyZYNbQTg"
}
"""