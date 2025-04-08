from wagtail import hooks
from wagtail.admin.menu import MenuItem

from django.urls import reverse


@hooks.register("register_admin_menu_item")
def register_manage_menu_item():
    return MenuItem(
        "Account security",
        reverse("hidp_account_management:manage_account"),
        icon_name="password",
        order=10000,
    )
