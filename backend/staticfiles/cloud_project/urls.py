from django.contrib import admin
from django.urls import path
from django.urls import include
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from drf_yasg.generators import OpenAPISchemaGenerator
from django.conf import settings # Zubair Edits
from django.conf.urls.static import static #Zubair edits


class CustomSchemaGenerator(OpenAPISchemaGenerator):
    def get_schema(self, request=None, public=True):
        schema = super().get_schema(request, public)
        if schema:
            schema.securityDefinitions = {
                'Bearer': {
                    'type': 'apiKey',
                    'name': 'Authorization',
                    'in': 'header',
                    'description': 'JWT Authentication. Use format: Bearer <your_jwt_token_here>'
                }
            }
            schema.security = [{'Bearer': []}]
        return schema

schema_view = get_schema_view(
    openapi.Info(
    title='MSIS Cloud API',
    default_version='v1.0',
    description='MSIS Cloud Solution API documentation',
    terms_of_service='http://www.msislab.com/policies/terms/',
    contact=openapi.Contact(email="info@msislab.com"),
    license=openapi.License(name="BSD License"),
    ),
    public=True,
    generator_class=CustomSchemaGenerator,  # Use the custom schema generator
    permission_classes=(permissions.AllowAny,),
)


urlpatterns = [
    path('swagger', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('redoc', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
    path('admin', admin.site.urls),
    path('', include('msis_app.urls')),
    path('api-auth/', include('rest_framework.urls')),
]
#### Zubair Edits
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root = settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root = settings.STATIC_URL)

