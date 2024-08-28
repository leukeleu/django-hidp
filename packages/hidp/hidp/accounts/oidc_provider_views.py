from oauth2_provider import views as oauth2_views


class RPInitiatedLogoutView(oauth2_views.RPInitiatedLogoutView):
    template_name = "hidp/accounts/logout_confirm.html"
