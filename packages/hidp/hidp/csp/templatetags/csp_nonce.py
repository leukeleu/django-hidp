from django import template

register = template.Library()


@register.simple_tag(takes_context=True)
def csp_nonce(context):
    # if it's not an attribute on the context object,
    # try looking for manually inserted request object
    request = getattr(context, "request", None) or context["request"]
    return getattr(request, "hidp_csp_nonce", None)
