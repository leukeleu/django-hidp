from rest_framework.views import APIView

from django.views.decorators.csrf import csrf_protect


class CSRFProtectedAPIView(APIView):
    """
    API view enforcing CSRF validation.

    By default, DRF APIViews are made exempt from CSRF checks by setting `csrf_exempt`
    to True. This class resets this behaviour and enforces CSRF validation on all
    requests.
    """

    @classmethod
    def as_view(cls, **initkwargs):
        view = super().as_view(**initkwargs)
        view.csrf_exempt = False
        return csrf_protect(view)
