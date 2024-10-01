from django import template

register = template.Library()


@register.simple_tag(takes_context=True)
def csp_nonce(context):
    return getattr(context.request, "hidp_csp_nonce", None)
