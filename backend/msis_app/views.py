import logging
from collections import defaultdict
from datetime import datetime, timedelta
from django.db.models import Count, Case, When, IntegerField, Max, Q, F
from django.db.models.functions import TruncHour, TruncDay
from django.http import Http404
from django.utils import timezone
import pytz
from django.core.mail import send_mail
from django.shortcuts import get_object_or_404
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from rest_framework import generics
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.schemas.openapi import AutoSchema
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView

from .serializers import *

logger = logging.getLogger(__name__)

caching_time = 5  # in minutes


# cache_key_machine = "machines_data_cache"
# cache_key_users = "users_list"

class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            # Use the serializer to validate and get data
            data = serializer.validated_data
            return custom_response(True, 200, 'Token obtained successfully', data)
        else:
            return custom_response(False, 400, 'Token obtain failed', serializer.errors)


class RegisterView(generics.CreateAPIView):
    serializer_class = RegisterSerializer
    permission_classes = [AllowAny]
    schema = AutoSchema()

    def get_serializer_context(self):
        context = super().get_serializer_context()
        context['request'] = self.request
        return context

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            # Save the new user and return a custom response
            self.perform_create(serializer)
            # users = cache.get(cache_key_users)
            # if users:
            #     logger.info("clearing users_list cache")
            #     cache.delete(cache_key_users)
            # headers = self.get_success_headers(serializer.data)
            return custom_response(True, 201, "User registered successfully.", serializer.data)
        else:
            # Return a custom error response
            return custom_response(False, 400,
                                   'Registration failed.',
                                   serializer.errors)


class UserView(APIView):
    @swagger_auto_schema(
        responses={

            200: openapi.Response('User details were retrieved successfully', UserSerializer(many=True)),
            400: 'Bad Request',
            500: 'Internal Server Error',
        }
    )
    def get(self, request):
        user = request.user
        if not user.is_superuser and not user.is_staff:
            return Response({"message": "Only super admin and manager can do this operation"},
                            status=status.HTTP_403_FORBIDDEN)
        # users = cache.get(cache_key_users)
        # if not users:
        users = User.objects.defer('password').prefetch_related('factories').select_related('approved_by',
                                                                                            'updated_by').all()
        # cache.set(cache_key_users, users, timeout=60 * caching_time)
        serializer = UserSerializer(users, many=True)
        return Response(list(serializer.data), status=status.HTTP_200_OK)


class UserDetailView(APIView):
    @swagger_auto_schema(
        operation_description="Retrieve user details by its ID",
        responses={
            200: openapi.Response('User details were retrieved successfully', UserSerializer),
            400: 'Invalid request',
            404: 'Requested user was not found'
        }
    )
    def get(self, request, user_id):
        user = request.user
        if not (user.is_superuser or user.is_staff) and user.id != user_id:
            return Response({"message": "Only super admin and manager can do this operation"},
                            status=status.HTTP_403_FORBIDDEN)
        user = get_object_or_404(User, id=user_id)
        serializer = UserSerializer(user)
        return Response(serializer.data)

    @swagger_auto_schema(
        operation_description='Change user details by ID',
        request_body=UserSerializer,
        responses={
            200: openapi.Response('User was updated successfully', UserSerializer),
            400: 'Invalid request',
            404: 'User was not found'
        }
    )
    def put(self, request, user_id):
        user = request.user
        if not (user.is_superuser or user.is_staff) and user.id != user_id:
            return Response({"message": "Only super admin and manager can do this operation"},
                            status=status.HTTP_403_FORBIDDEN)
        user = get_object_or_404(User, id=user_id)
        serializer = UserSerializer(user, data=request.data, partial=True)

        if serializer.is_valid():
            if 'is_deleted' in request.data and user.is_deleted != request.data['is_deleted']:
                user.is_deleted = request.data.get('is_deleted')
            if 'password' in request.data and len(request.data.get('password').strip()) == 0:
                return Response({"error": "Password cannot be empty string"}, status=status.HTTP_400_BAD_REQUEST)
            if 'password' in request.data:
                user.set_password(request.data['password'])
            if not user.is_activated and request.user.is_superuser:
                user.approved_by = request.user
            # users = cache.get(cache_key_users)
            # if users:
            #     logger.info("clearing users_list cache")
            #     cache.delete(cache_key_users)
            serializer.save(updated_by=request.user)
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(generics.GenericAPIView):
    permission_classes = [AllowAny]  # No authentication required to log in
    serializer_class = LoginSerializer

    def post(self, request, *args, **kwargs):
        # Validate login credentials
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data['user']  # Retrieve user from validated data
            # Create JWT tokens
            refresh = RefreshToken.for_user(user)
            serializer = UserSerializer(user)
            return custom_response(True, 200, 'Operation successful', {
                'refresh': str(refresh),
                'token': str(refresh.access_token),
                'user': serializer.data
            })
        else:
            try:
                error_msg = str(serializer.errors['non_field_errors'][0])
                return custom_response(False, 404, error_msg)
            except Exception as e:
                logger.error(e)
                return custom_response(False, 404, "Invalid credentials", serializers.errors)


class PasswordResetRequestView(APIView):
    permission_classes = [AllowAny]  # No authentication required to request password reset
    serializer_class = PasswordResetRequestSerializer

    @swagger_auto_schema(request_body=PasswordResetRequestSerializer)
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            user = User.objects.get(email=email)

            token = PasswordResetTokenGenerator().make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            reset_link = f"{request.scheme}://{request.get_host()}/reset-password/{uid}/{token}/"

            # Send the reset link via email
            send_mail(
                subject="Password Reset Request",
                message=f"Use this link to reset your password: {reset_link}",
                from_email="your-email@example.com",
                recipient_list=[email],
            )

            return custom_response(True, 200, 'Password reset link has been sent to your email.')
        else:
            return custom_response(False, 404, 'Invalid credentials', serializer.errors)


class PasswordResetView(generics.GenericAPIView):
    permission_classes = [AllowAny]  # No authentication required to reset password
    serializer_class = PasswordResetSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return custom_response(True, 200, "Password has been reset successfully.")
        else:
            return custom_response(False, 404, 'Invalid crendentials', serializer.errors)


class FindUsernameView(generics.GenericAPIView):
    permission_classes = [AllowAny]  # No authentication required to find username
    serializer_class = FindUsernameSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            username = serializer.validated_data['email']
            print('my serializer: ', username)
            return custom_response(True, 200, 'Operation successful', {"username": username})
        else:
            return custom_response(False, 404, 'User not found', serializer.errors)


class FactoryView(APIView):
    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'name': openapi.Schema(type=openapi.TYPE_STRING),
                'location': openapi.Schema(type=openapi.TYPE_STRING),
            },
        ),
        responses={201: 'Factory created successfully', 400: 'Invalid request', 500: 'Error'},
    )
    def post(self, request):
        user = request.user
        if not (user.is_superuser or user.is_staff):
            return Response({"message": "Only super admin and manager can do this operation"},
                            status=status.HTTP_403_FORBIDDEN)
        data = request.data
        name = data.get('name')
        location = data.get('location')

        if not name or not location:
            return custom_response(False, 400, 'Both name and location are required.')

        factory = Factory.objects.create(
            name=name,
            location=location
        )

        superusers = User.objects.filter(is_superuser=True)
        for superuser in superusers:
            superuser.factories.add(factory)

        return custom_response(True, 201, 'Factory data saved successfully', {'factory_id': factory.id})

    @swagger_auto_schema(
        responses={
            200: openapi.Schema(type=openapi.TYPE_ARRAY, items=openapi.Schema(type=openapi.TYPE_OBJECT, properties={
                'id': openapi.Schema(type=openapi.TYPE_INTEGER),
                'name': openapi.Schema(type=openapi.TYPE_STRING),
                'location': openapi.Schema(type=openapi.TYPE_STRING),
                'is_deleted': openapi.Schema(type=openapi.TYPE_BOOLEAN),
            }))}
    )
    def get(self, request):
        user = request.user
        user_factories = user.factories.all().values('id', 'name', 'location')
        return Response(list(user_factories), status=status.HTTP_200_OK)


class FactoryDetailView(APIView):
    @swagger_auto_schema(
        operation_description="Retrieve factory details by its ID",
        responses={200: 'Factory details was retrieved successfully', 400: 'Invalid request',
                   404: 'Requested factory was not found'
                   }
    )
    def get(self, request, factory_id):
        user = request.user
        try:
            factory = get_object_or_404(user.factories.all(), id=factory_id)
        except Http404:
            return Response(
                {"message": f"Factory not found with ID {factory_id} or it is not associated with the user."},
                status=status.HTTP_404_NOT_FOUND
            )
        serializer = FactorySerializer(factory)
        return Response(serializer.data)

    @swagger_auto_schema(
        operation_description='Change factory details by ID',
        request_body=FactorySerializer,
        responses={200: openapi.Response('Factory was updated successfully', FactorySerializer), 400: 'Invalid request',
                   404: 'Factory was not found'
                   }
    )
    def put(self, request, factory_id):
        user = request.user
        if not user.is_superuser and not user.is_staff:
            return Response({"message": "Only super admin and manager can do this operation"},
                            status=status.HTTP_403_FORBIDDEN)
        try:
            factory = get_object_or_404(user.factories.all(), id=factory_id)
        except Http404:
            return Response(
                {"message": f"Factory not found with ID {factory_id} or it is not associated with the user."},
                status=status.HTTP_404_NOT_FOUND
            )
        serializer = FactorySerializer(factory, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @swagger_auto_schema(
        operation_description="Delete a factory by its ID",
        responses={
            200: openapi.Response('Factory was deleted successfully'),
            404: openapi.Response('Factory Not Found'),
            403: openapi.Response('Only super admin and manager can do this operation')
        }
    )
    def delete(self, request, factory_id):
        """
        Handle DELETE requests to delete a machine with its ID.

        Args:
            request (Request): The incoming request containing the machine ID.

        Returns:
            Response: A DRF Response object with the success message.
        """
        user = request.user
        if not (user.is_staff or user.is_superuser):
            return Response({"message": "Only super admin and manager can do this operation"},
                            status=status.HTTP_403_FORBIDDEN)
        factory = get_object_or_404(Factory, id=factory_id)
        if user.is_superuser or user.factories.filter(id=factory.id).exists():
            factory.delete()
            return Response({
                'message': f'The factory with ID: {factory_id} was successfully deleted'
            }, status=status.HTTP_200_OK)
        else:
            return Response({
                'message': f'The factory with ID: {factory_id} is not associated with the currently logged in user!'
            }, status=status.HTTP_403_FORBIDDEN)


class FactoryNameIdView(APIView):
    """
    API view to retrieve only factory names and IDs.
    """

    # Allow access without authentication
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_description="Retrieve a list of factories with only name and ID.",
        responses={200: openapi.Schema(
            type=openapi.TYPE_ARRAY,
            items=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'id': openapi.Schema(type=openapi.TYPE_INTEGER, description='Factory ID'),
                    'name': openapi.Schema(type=openapi.TYPE_STRING, description='Factory Name'),
                }
            )
        )}
    )
    def get(self, request):
        # Fetch only id and name from the Factory model

        factories_list = Factory.objects.values('id', 'name')
        return Response(list(factories_list), status=status.HTTP_200_OK)


class CategoryView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'name': openapi.Schema(type=openapi.TYPE_STRING),
                'description': openapi.Schema(type=openapi.TYPE_STRING),
            },
        ),
        responses={201: 'Category created successfully', 400: 'Invalid request', 500: 'Error'},
    )
    def post(self, request):
        self.check_permissions(request)
        # self.che
        user = request.user
        if not (user.is_superuser or user.is_staff):
            return Response({"message": "Only super admin and manager can do this operation"},
                            status=status.HTTP_403_FORBIDDEN)
        data = request.data
        name = data.get('name')

        if not name:
            return custom_response(False, 400, 'Category name is required.')

        category = Category.objects.create(
            name=name,
            description=data.get('description', None)
        )
        serializer = CategorySerializer(category)
        return custom_response(True, 201, 'Category created successfully', serializer.data)

    permission_classes = []

    @swagger_auto_schema(
        responses={
            200: openapi.Schema(type=openapi.TYPE_ARRAY, items=openapi.Schema(type=openapi.TYPE_OBJECT, properties={
                'id': openapi.Schema(type=openapi.TYPE_INTEGER),
                'name': openapi.Schema(type=openapi.TYPE_STRING),
                'description': openapi.Schema(type=openapi.TYPE_STRING)
            }))}
    )
    def get(self, request):
        categories = Category.objects.all()
        serializer = CategorySerializer(categories, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class CategoryDetailView(APIView):
    @swagger_auto_schema(
        responses={
            200: openapi.Schema(type=openapi.TYPE_ARRAY, items=openapi.Schema(type=openapi.TYPE_OBJECT, properties={
                'id': openapi.Schema(type=openapi.TYPE_INTEGER),
                'name': openapi.Schema(type=openapi.TYPE_STRING),
                'description': openapi.Schema(type=openapi.TYPE_STRING)
            }))}
    )
    def get(self, request, category_id):
        try:
            category = Category.objects.get(pk=category_id)
        except Category.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)
        serializer = CategorySerializer(category)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @swagger_auto_schema(
        operation_description='Change category details by ID',
        request_body=CategorySerializer,
        responses={
            200: openapi.Response('Category was updated successfully', CategorySerializer),
            400: 'Invalid request',
            404: 'Category was not found'
        }
    )
    def put(self, request, category_id):
        user = request.user
        if not (user.is_staff or user.is_superuser):
            return Response({"message": "Only super admin and manager can do this operation"},
                            status=status.HTTP_403_FORBIDDEN)
        try:
            category = Category.objects.get(pk=category_id)
        except Category.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)

        serializer = CategorySerializer(category, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @swagger_auto_schema(
        operation_description="Delete a category by its ID",
        responses={
            200: openapi.Response('Category was deleted successfully'),
            404: openapi.Response('Category Not Found'),
            403: openapi.Response('Only super admin and manager can do this operation')
        }
    )
    def delete(self, request, category_id):
        user = request.user
        if not (user.is_staff or user.is_superuser):
            return Response({"message": "Only super admin and manager can do this operation"},
                            status=status.HTTP_403_FORBIDDEN)
        try:
            user = request.user

            category = Category.objects.get(pk=category_id)
            category.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        except Category.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)


class MachineView(APIView):
    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'name': openapi.Schema(type=openapi.TYPE_STRING),
                'title': openapi.Schema(type=openapi.TYPE_STRING),
                'ip_address': openapi.Schema(type=openapi.TYPE_STRING),
                'location': openapi.Schema(type=openapi.TYPE_STRING),
                'category': openapi.Schema(type=openapi.TYPE_STRING),
                'factory': openapi.Schema(type=openapi.TYPE_STRING)
            },
        ),
        responses={
            201: 'Machine created successfully',
            400: 'Invalid request',
            403: 'Only super admin and manager can do this operation',
            404: 'Factory not found',
            500: 'Error'
        },
    )
    def post(self, request):
        user = request.user
        if not (user.is_staff or user.is_superuser):
            return Response({"message": "Only super admin and manager can do this operation"},
                            status=status.HTTP_403_FORBIDDEN)
        data = request.data
        name = data.get('name')
        title = data.get('title')
        ip_address = data.get('ip_address')
        location = data.get('location')
        factory_name = data.get('factory')
        category_name = data.get('category')

        if not (name and ip_address and location and factory_name and category_name):
            return Response({'status': 'error', 'message': 'All fields are required.'},
                            status=status.HTTP_400_BAD_REQUEST)

        try:
            factory = Factory.objects.get(name=factory_name)
            category = Category.objects.get(name=category_name)
        except Category.DoesNotExist:
            return Response({'status': 'error', 'message': f'Category not found with given name: {category_name}.'},
                            status=status.HTTP_404_NOT_FOUND)
        except Factory.DoesNotExist:
            return Response({'status': 'error', 'message': f'Factory not found with given name: {factory_name}.'},
                            status=status.HTTP_404_NOT_FOUND)

        machine = Machine.objects.create(
            name=name,
            title=title,
            ip_address=ip_address,
            location=location,
            category=category,
            factory=factory
        )
        # response_data = cache.get(cache_key_machine)
        # if response_data:
        #     logger.info("Clearing the cache for machine data")
        #     cache.delete(cache_key_machine)
        return Response({'status': 'success', 'message': 'New machine added successfully', 'machine_id': machine.id},
                        status=status.HTTP_201_CREATED)

    # permission_classes = [AllowAny] # dev testing
    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter(
                'factory_id',
                openapi.IN_QUERY,
                description="(Optional) Filter by factory ID",
                type=openapi.TYPE_INTEGER,
                required=False
            )
        ],
        responses={
            200: openapi.Response(
                description="List of machines with data counts",
                schema=openapi.Schema(
                    type=openapi.TYPE_ARRAY,
                    items=openapi.Schema(
                        type=openapi.TYPE_OBJECT,
                        properties={
                            'id': openapi.Schema(type=openapi.TYPE_INTEGER),
                            'name': openapi.Schema(type=openapi.TYPE_STRING),
                            'title': openapi.Schema(type=openapi.TYPE_STRING),
                            'ip_address': openapi.Schema(type=openapi.TYPE_STRING),
                            'location': openapi.Schema(type=openapi.TYPE_STRING),
                            'factory': openapi.Schema(type=openapi.TYPE_INTEGER),
                            'is_deleted': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                            'status': openapi.Schema(type=openapi.TYPE_STRING, description='Machine status (on/off)'),
                            'detection_count': openapi.Schema(type=openapi.TYPE_INTEGER),
                            'anomaly_count': openapi.Schema(type=openapi.TYPE_INTEGER),
                            'camera_count': openapi.Schema(type=openapi.TYPE_INTEGER),
                            'last_reset_time': openapi.Schema(type=openapi.TYPE_STRING, format=openapi.FORMAT_DATETIME),
                        }
                    )
                )
            ),
            400: 'Bad Request',
            500: 'Internal Server Error',
        }
    )
    def get(self, request):
        user = request.user
        # user = User.objects.get(id=7) # dev tessting operator1 user
        user_factory_id = user.factories.first().id
        # if no factory_id is provided get user's 1st factory_id
        factory_id = request.query_params.get('factory_id', user_factory_id)
        # logger.info(f"user default factory id: {user_factory_id}, user input: {request.query_params.get('factory_id')}")

        # Get the current time in the local timezone
        current_time = timezone.now().astimezone(timezone.get_current_timezone())

        # logger.info(f"current time: {current_time}")
        if current_time.hour < 8:
            # Before 08:00 AM, set shift_start to yesterday at 08:00 PM
            shift_start = (current_time - timedelta(days=1)).replace(hour=20, minute=0, second=0, microsecond=0)
        elif current_time.hour < 20:
            # Between 08:00 AM and 08:00 PM, set shift_start to today at 08:00 AM
            shift_start = current_time.replace(hour=8, minute=0, second=0, microsecond=0)
        else:
            # After 08:00 PM, set shift_start to today at 08:00 PM
            shift_start = current_time.replace(hour=20, minute=0, second=0, microsecond=0)
        # logger.info(f"start shift: {shift_start}")

        # if factory_id is not associated with user's factory, do not handle request and return 403 Forbidden response
        if not (user.is_superuser or user.factories.filter(id=factory_id).exists()):
            logger.warning(f'[MachineView:get] The factory with ID: {factory_id} is not associated with your factory!')
            return Response({
                'message': f'The factory with ID: {factory_id} is not associated with your factory!'
            }, status=status.HTTP_403_FORBIDDEN)
        elif user.is_superuser or user.is_staff:
            machines = Machine.objects.filter(factory_id=factory_id).annotate(
                camera_count=Count('cameras', filter=Q(cameras__is_deleted=False))
            )
        else:
            machines = Machine.objects.filter(factory_id=factory_id, is_deleted=False).annotate(
                camera_count=Count('cameras', filter=Q(cameras__is_deleted=False))
            )

        model_classes = {
            'airbag': DAirbag,
            'mold': DMold,
            'pcb': DPcb,
            'pin': DPinArrival,
            'reel-packaging': DReelPackaging,
        }

        for machine in machines:
            if not machine.last_reset_time or machine.last_reset_time < shift_start:
                machine.last_reset_time = shift_start  # Update in memory

        # Create `machine_info_map` after updating `last_reset_time`
        machine_info_map = {machine.id: machine for machine in machines}

        # Aggregate data from multiple model classes
        data = defaultdict(dict)
        for key, model_class in model_classes.items():
            model_data = model_class.objects.filter(
                machine__in=machine_info_map.keys(),
                timestamp__gte=F("machine__last_reset_time")
            ).values('machine').annotate(
                anomaly_count=Count(Case(When(status='NG', then=1), output_field=IntegerField())),
                detection_count=Count("id"),
                last_entry_time=Max('timestamp')
            )
            for entry in model_data:
                machine_id = entry['machine']
                data[machine_id][key] = {
                    'anomaly_count': entry.get('anomaly_count', 0),
                    'detection_count': entry.get('detection_count', 0),
                    'last_entry_time': entry['last_entry_time']
                }

        time_threshold = timezone.now() - timedelta(minutes=5)
        categorized_data = defaultdict(lambda: {"machines": [], "total_anomaly_count": 0, "total_detection_count": 0})

        for machine_id, machine_data in machine_info_map.items():
            # Determine the last reset timestamp
            last_reset_time = machine_data.last_reset_time \
                if machine_data and machine_data.last_reset_time > shift_start else shift_start
            anomaly_count = 0
            detection_count = 0
            machine_status = "off"

            # Collect relevant data if available
            if machine_id in data:
                for category_data in data[machine_id].values():
                    anomaly_count += category_data.get('anomaly_count', 0)
                    detection_count += category_data.get('detection_count', 0)
                    if category_data['last_entry_time'] and category_data['last_entry_time'] >= time_threshold:
                        machine_status = "on"

            # Add machine details to response structure
            machine_entry = {
                "id": machine_data.id,
                "name": machine_data.name,
                "title": machine_data.title,
                "ip_address": machine_data.ip_address,
                "location": machine_data.location,
                "category": machine_data.category.name,
                "factory": machine_data.factory.name,
                "is_deleted": machine_data.is_deleted,
                "status": machine_status,
                "camera_count": machine_data.camera_count,
                "detection_count": detection_count,
                "anomaly_count": anomaly_count,
                "last_reset_time": last_reset_time
            }
            categorized_data[machine_data.category.name]["machines"].append(machine_entry)
            categorized_data[machine_data.category.name]["total_anomaly_count"] += anomaly_count
            categorized_data[machine_data.category.name]["total_detection_count"] += detection_count

        # Finalize response data
        response_data = {
            category: {
                "machines": data["machines"],
                "total_anomaly_count": data["total_anomaly_count"],
                "total_detection_count": data["total_detection_count"],
            }
            for category, data in categorized_data.items()
        }
        return Response(response_data, status=status.HTTP_200_OK)


class MachineDetailsView(APIView):
    @swagger_auto_schema(
        operation_description="Retrieve machine details by its ID",
        responses={200: 'Machine details was retrieved successfully',
                   400: 'Invalid request',
                   404: 'Requested factory was not found'}
    )
    def get(self, request, machine_id):
        user = request.user
        if not (user.is_staff or user.is_superuser):
            return Response({"message": "Only super admin and manager can do this operation"},
                            status=status.HTTP_403_FORBIDDEN)
        machine = get_object_or_404(Machine, id=machine_id)
        if user.is_superuser or user.factories.filter(id=machine.factory.id).exists():
            serializer = MachineSerializer(machine)
            return Response(serializer.data)
        else:
            return Response({
                'message': f'The machine with ID: {machine_id} is not associated with your factory!'
            }, status=status.HTTP_403_FORBIDDEN)

    @swagger_auto_schema(
        operation_description="Update details of an existing machine",
        request_body=MachineSerializer,
        responses={
            200: openapi.Response('Machine details updated successfully', MachineSerializer),
            400: 'Bad Request',
            404: 'Machine Not Found',
            500: 'Internal Server Error',
        }
    )
    def put(self, request, machine_id):
        """
        Handle PUT requests to update machine's details.

        Args:
            request (Request): The incoming request containing the machine details.

        Returns:
            Response: A DRF Response object with the update result.
        """
        try:
            user = request.user
            if not (user.is_staff or user.is_superuser):
                return Response({"message": "Only super admin and manager can do this operation"},
                                status=status.HTTP_403_FORBIDDEN)
            machine = get_object_or_404(Machine, id=machine_id)
            if user.is_superuser or user.factories.filter(id=machine.factory.id).exists():
                data = request.data.copy()
                factory_name = data.get('factory', None)
                # response_data = cache.get(cache_key_machine)
                # if response_data:
                #     logger.info("Clearing the cache for machine data")
                #     cache.delete(cache_key_machine)
                if factory_name is not None:
                    factory = Factory.objects.filter(
                        name=factory_name).first()
                    if not factory:
                        return Response({'error': f'Factory not found with the given name: {factory_name}'},
                                        status=status.HTTP_404_NOT_FOUND)
                    data['factory'] = factory.id
                is_deleted = data.get('is_deleted', None)
                if is_deleted is None:
                    data['is_deleted'] = machine.is_deleted
                serializer = MachineSerializer(machine, data=data, partial=True)
                if serializer.is_valid():
                    serializer.save()
                    return Response(serializer.data, status=status.HTTP_200_OK)
                return Response({
                    'message': 'Failed to update machine details',
                    'errors': serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({
                    'message': f'The machine with ID: {machine_id} is not associated with your factory!'
                }, status=status.HTTP_403_FORBIDDEN)
        except Exception as e:
            return Response(f'Error: {str(e)}', status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @swagger_auto_schema(
        operation_description="Delete a machine by its ID",
        responses={
            200: openapi.Response('Machine was deleted successfully'),
            404: openapi.Response('Machine Not Found'),
            403: openapi.Response('Only super admin and manager can do this operation')
        }
    )
    def delete(self, request, machine_id):
        """
        Handle DELETE requests to delete a machine with its ID.

        Args:
            request (Request): The incoming request containing the machine ID.

        Returns:
            Response: A DRF Response object with the success message.
            :param machine_id:
        """
        user = request.user
        if not (user.is_staff or user.is_superuser):
            return Response({"message": "Only super admin and manager can do this operation"},
                            status=status.HTTP_403_FORBIDDEN)
        machine = get_object_or_404(Machine, id=machine_id)
        if user.is_superuser or user.factories.filter(id=machine.factory.id).exists():
            machine.delete()
            return Response({
                'message': f'The machine with ID: {machine_id} was successfully deleted'
            }, status=status.HTTP_200_OK)
        else:
            return Response({
                'message': f'The machine with ID: {machine_id} is not associated with your factory!'
            }, status=status.HTTP_403_FORBIDDEN)


class MachineNgCountResetView(APIView):
    @swagger_auto_schema(
        operation_description="Reset NG counts of an existing machine",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'category': openapi.Schema(type=openapi.TYPE_STRING, description="Machine category name"),
                'machine_id': openapi.Schema(type=openapi.TYPE_INTEGER, description="Machine ID"),
                'undo': openapi.Schema(type=openapi.TYPE_BOOLEAN, description="Undo reset", default=False),
            },
            required=[]  # Specify any required properties here, e.g., required=['machine_id']
        ),
        responses={
            200: openapi.Response('NG count was reset successfully'),
            400: 'Bad request',
            404: 'Machine Not Found',
            500: 'Internal Server Error',
        }
    )
    def post(self, request):
        """
        Handle POST requests to reset machine's NG counts.
        """
        try:
            category = request.data.get('category', None)
            machine_id = request.data.get('machine_id', None)
            undo = request.data.get('undo', False)

            logger.info(f"Reset machine NG count for machine ID {machine_id} or category '{category}, undo reset {undo}'")
            if not(category or machine_id):
                return Response({
                    'message': f'One of machine ID {machine_id} or category {category} is not required to reset NG counts'
                }, status=status.HTTP_400_BAD_REQUEST)
            user = request.user
            if category:
                try:
                    category_instance = Category.objects.get(name=category)
                    machines = Machine.objects.filter(category=category_instance, factory__in=user.factories.all())

                    for machine in machines:
                        machine.last_reset_time = None if undo else timezone.now()
                        machine.save()

                    return Response({
                        'message': f"{'Undo' if undo else 'Reset'} successful for all machines in category '{category}'"
                    }, status=status.HTTP_200_OK)

                except Category.DoesNotExist:
                    return Response({'message': f"Category '{category}' not found"}, status=status.HTTP_404_NOT_FOUND)

            # Reset based on machine_id if category is not provided
            else:
                machine = get_object_or_404(Machine, id=machine_id)

                if user.is_superuser or user.factories.filter(id=machine.factory.id).exists():
                    machine.last_reset_time = None if undo else timezone.now()
                    machine.save()
                    return Response({
                        'message': f"{'Undo' if undo else 'Reset'} successful for machine_id '{machine_id}'"
                    }, status=status.HTTP_200_OK)
                else:
                    return Response({
                        'message': f'The machine with ID: {machine_id} is not associated with your factory!'
                    }, status=status.HTTP_403_FORBIDDEN)
        except Exception as e:
            logger.error(f"Error resetting NG count: {e}")
            return Response({'error': f"Error: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class CameraView(APIView):
    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'name': openapi.Schema(type=openapi.TYPE_STRING),
                'serial_no': openapi.Schema(type=openapi.TYPE_STRING),
                'machine_name': openapi.Schema(type=openapi.TYPE_STRING),
            },
        ),
        responses={201: 'Camera created successfully', 400: 'Invalid request', 500: 'Error'},
    )
    def post(self, request):
        user = request.user
        if not (user.is_staff or user.is_superuser):
            return Response({"message": "Only super admin and manager can do this operation"},
                            status=status.HTTP_403_FORBIDDEN)
        data = request.data
        name = data.get('name')
        serial_no = data.get('serial_no')
        machine_name = data.get('machine_name')
        if not name or not serial_no or not machine_name:
            return Response({'status': 'error', 'message': 'All fields are required.'},
                            status=status.HTTP_400_BAD_REQUEST)
        try:
            machine = Machine.objects.get(name=machine_name)
            factory = machine.factory
        except Machine.DoesNotExist:
            return Response({'status': 'error', 'message': 'Machine not found.'}, status=status.HTTP_400_BAD_REQUEST)
        if user.is_superuser or user.factories.filter(id=machine.factory.id).exists():
            cameras_machine = Camera.objects.filter(machine=machine).count()
            ref_id = cameras_machine + 1
            camera = Camera.objects.create(
                ref_id=ref_id,
                name=name,
                serial_no=serial_no,
                machine=machine,
                factory=factory
            )
        else:
            return Response({
                'message': f'The machine with name: {machine_name} is not associated with your factory!'
            }, status=status.HTTP_403_FORBIDDEN)
        # response_data = cache.get(cache_key_machine)
        # if response_data:
        #     cache.delete(cache_key_machine)
        return Response({'status': 'success', 'message': 'Camera data saved successfully', 'camera_id': camera.id},
                        status=status.HTTP_201_CREATED)

    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter(
                'machine_id',
                openapi.IN_QUERY,
                description="(Optional) Filter by machine ID",
                type=openapi.TYPE_INTEGER,
                required=False
            ),
        ],
        responses={
            200: openapi.Schema(type=openapi.TYPE_ARRAY, items=openapi.Schema(type=openapi.TYPE_OBJECT, properties={
                'id': openapi.Schema(type=openapi.TYPE_INTEGER),
                'ref_id': openapi.Schema(type=openapi.TYPE_STRING),
                'name': openapi.Schema(type=openapi.TYPE_STRING),
                'serial_no': openapi.Schema(type=openapi.TYPE_STRING),
                'machine__name': openapi.Schema(type=openapi.TYPE_STRING),
                'factory__name': openapi.Schema(type=openapi.TYPE_STRING),
                'is_deleted': openapi.Schema(type=openapi.TYPE_BOOLEAN),
            }))}
    )
    def get(self, request):
        machine_id = request.query_params.get('machine_id', None)
        query = Camera.objects
        if machine_id is not None:
            query = query.filter(machine_id=machine_id)
        cameras_list = query.values('id', 'ref_id', 'name', 'serial_no', 'machine__name', 'factory__name', 'is_deleted')

        return Response(list(cameras_list), status=status.HTTP_200_OK)


class CameraDetailsView(APIView):
    @swagger_auto_schema(
        operation_description="Retrieve machine details by its ID",
        responses={200: openapi.Response('Camera details were retrieved successfully', CameraSerializer),
                   400: 'Invalid request',
                   404: 'Requested camera was not found'}
    )
    def get(self, request, camera_id):
        camera = get_object_or_404(Camera, id=camera_id)
        serializer = CameraSerializer(camera)
        return Response(serializer.data)

    @swagger_auto_schema(
        operation_description="Update details of an existing camera.",
        request_body=CameraSerializer,
        responses={
            200: openapi.Response('Camera details updated successfully', CameraSerializer),
            400: 'Bad Request',
            404: 'Camera Not Found',
            500: 'Internal Server Error',
        }
    )
    def put(self, request, camera_id):
        """
        Handle PUT requests to update a camera's details using camera_id.

        Args:
            request (Request): The incoming request containing the camera details.

        Returns:
            Response: A DRF Response object with the update result.
        """
        try:
            camera = get_object_or_404(Camera, id=camera_id)
            serializer = CameraSerializer(camera, data=request.data, partial=True)

            machine_id = request.data.get('machine', None)
            if machine_id is not None:
                if not Machine.objects.filter(id=machine_id).exists():
                    return Response({'error': f'Machine not found with given ID: {machine_id}'},
                                    status=status.HTTP_404_NOT_FOUND)
                camera.machine_id = machine_id
            if serializer.is_valid():
                serializer.save()
                # response_data = cache.get(cache_key_machine)
                # if response_data:
                #     cache.delete(cache_key_machine)
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response({
                'message': 'Failed to update machine details',
                'errors': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Error updating camera (ID: {camera_id}): {str(e)}")
            return Response({'error': f'An error occurred while updating the camera details: {str(e)}'},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @swagger_auto_schema(
        operation_description="Delete a camera by its ID",
        responses={
            200: openapi.Response('Camera was deleted successfully'),
            404: openapi.Response('Camera Not Found'),
            403: openapi.Response('Only super admin and manager can do this operation')
        }
    )
    def delete(self, request, camera_id):
        """
        Handle DELETE requests to delete a camera with its ID.

        Args:
            request (Request): The incoming request containing the camera ID.

        Returns:
            Response: A DRF Response object with the success message.
        """
        user = request.user
        if not (user.is_staff or user.is_superuser):
            return Response({"message": "Only super admin and manager can do this operation"},
                            status=status.HTTP_403_FORBIDDEN)
        camera = get_object_or_404(Camera, id=camera_id)
        if user.is_superuser or user.factories.filter(id=camera.factory.id).exists():
            camera.delete()
            return Response({
                'message': f'The camera with ID: {camera_id} was successfully deleted'
            }, status=status.HTTP_200_OK)
        else:
            return Response({
                'message': f'The camera with ID: {camera_id} is not associated with your factory!'
            }, status=status.HTTP_403_FORBIDDEN)


class MachineStatsView(APIView):
    """Retrieve anomaly data for a given machine category, id and hour or day"""
    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter(
                'category',
                openapi.IN_PATH,
                description="Machine category name",
                type=openapi.TYPE_STRING
            ),
            openapi.Parameter(
                'type',
                openapi.IN_PATH,
                description="Type of data query: hourly or daily",
                type=openapi.TYPE_STRING
            ),
            openapi.Parameter(
                'machine_id',
                openapi.IN_PATH,
                description="ID of the machine to filter data",
                type=openapi.TYPE_INTEGER
            ),
            openapi.Parameter(
                'date',
                openapi.IN_QUERY,
                description="(Optional) Filter by date (YYYY-MM-DD)",
                type=openapi.TYPE_STRING,
                required=False
            )
        ],
        responses={
            200: openapi.Schema(type=openapi.TYPE_ARRAY, items=openapi.Schema(type=openapi.TYPE_OBJECT, properties={
                'hour': openapi.Schema(type=openapi.TYPE_STRING),
                'ng_count': openapi.Schema(type=openapi.TYPE_INTEGER),
            }))
        }
    )
    def get(self, request, category, type, machine_id):

        category = category.upper()
        type_input = type.upper()
        date_input = request.query_params.get('date', None)
        try:
            # Fetch the machine
            machine = Machine.objects.get(id=machine_id)
            date_input = datetime.strptime(date_input, "%Y-%m-%d") if date_input else timezone.now()
            date_str = date_input.strftime("%B %d, %Y") if type_input == 'HOURLY' else date_input.strftime("%B %Y")
        except Machine.DoesNotExist:
            return Response({'error': 'Machine not found.'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'error': f'Error: {str(e)}'}, status=status.HTTP_400_BAD_REQUEST)

        # if type_input == "HOURLY" and date_input.date() > timezone.now().date():
        #     logger.info('dates: ', date_input.date(), timezone.now().date())
        #     return Response({'error': f'Incorrect date was provided: {date_str}'},
        #                     status=status.HTTP_400_BAD_REQUEST)

        # logger.info(f"date: {date_input}, date_str: {date_str}")
        if not (machine_id and category):
            return Response({'error': 'Providing the "machine_id" and "category" is required.'},
                            status=status.HTTP_400_BAD_REQUEST)

        query = None
        if 'MOLD' in category:
            query = DMold.objects
        elif 'REEL' in category:
            query = DReelPackaging.objects
        elif 'AIRBAG' in category:
            query = DAirbag.objects
        elif 'PIN' in category:
            query = DPinArrival.objects
        elif 'PCB' in category:
            query = DPcb.objects
        else:
            return Response(f'Incorrect category provided: {category}', status=status.HTTP_400_BAD_REQUEST)

        if type_input == 'DAILY':
            date_input = datetime(date_input.year, date_input.month, 1)
            year_input = date_input.year
            if date_input.month == 12:
                year_input += 1
                next_month = 1
            else:
                next_month = date_input.month + 1
            next_month = datetime(year_input, next_month, 1)
            num_days = (next_month - timedelta(days=1)).day # last day of the month
            start_day = date_input
            end_day = start_day + timezone.timedelta(days=num_days)
            all_days = [(start_day + timedelta(days=i)).strftime('%Y-%m-%d') for i in range(num_days)]
            query = query.filter(
                machine=machine,
                status='NG',
                timestamp__range=[start_day, end_day]
            ).annotate(day=TruncDay('timestamp')).values('day').order_by('day').annotate(anomaly_count=Count('id'))
            data = {entry['day'].strftime('%Y-%m-%d'): entry['anomaly_count'] for entry in query}
            logger.info(data)
            result = {day: data.get(day, 0) for day in all_days}
        else:
            start_time = timezone.make_aware(datetime.combine(date_input, datetime.min.time()))
            end_time = start_time + timedelta(days=1)
            all_hours = [(start_time + timedelta(hours=i)).strftime('%H:00') for i in range(24)]
            query = query.filter(
                machine=machine,
                status='NG',
                timestamp__range=[start_time, end_time]
            ).annotate(hour=TruncHour('timestamp')).values('hour').order_by('hour').annotate(anomaly_count=Count('id'))
            data = {entry['hour'].strftime('%H:00'): entry['anomaly_count'] for entry in query}
            logger.info(data)
            result = {hour: data.get(hour, 0) for hour in all_hours}

        result = {"date": date_str, "data": result}
        return custom_response(True, 200, f"{type_input} data was successfully retrieved for machine: {machine_id}", result)


class MachineDataView(APIView):
    """Retrieve detections data for a given machine and camera"""

    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter(
                'machine_id',
                openapi.IN_PATH,
                description="ID of the machine to filter data",
                type=openapi.TYPE_INTEGER
            ),
            openapi.Parameter(
                'camera_id',
                openapi.IN_QUERY,
                description="(Optional) Filter by camera ID",
                type=openapi.TYPE_INTEGER,
                required=False
            ),
            openapi.Parameter(
                'n',
                openapi.IN_QUERY,
                description="(Optional) The number of latest records to retrieve",
                type=openapi.TYPE_INTEGER,
                required=False,
                default=100
            ),
        ],
        responses={
            200: openapi.Schema(type=openapi.TYPE_ARRAY, items=openapi.Schema(type=openapi.TYPE_OBJECT, properties={
                'id': openapi.Schema(type=openapi.TYPE_INTEGER),
                'camera_id': openapi.Schema(type=openapi.TYPE_INTEGER),
                'machine': openapi.Schema(type=openapi.TYPE_STRING),
                'status': openapi.Schema(type=openapi.TYPE_STRING),
                'proc_time': openapi.Schema(type=openapi.TYPE_STRING),
                'timestamp': openapi.Schema(type=openapi.TYPE_STRING),
            }))
        }
    )
    def get(self, request, machine_id):
        n = request.query_params.get('n', 100)
        camera_id = request.query_params.get('camera_id', None)

        if not machine_id:
            return Response({'error': 'Providing the "machine_id" is required.'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            # Fetch the machine
            machine = Machine.objects.get(id=machine_id)
            machine_name = machine.name.lower()
        except Machine.DoesNotExist:
            return Response({'error': 'Machine not found.'}, status=status.HTTP_404_NOT_FOUND)

        # Determine the appropriate model based on the machine name
        query = None
        if 'mold' in machine_name:
            query = DMold.objects.filter(machine=machine).order_by('-timestamp')
        elif 'reel' in machine_name:
            query = DReelPackaging.objects.filter(machine=machine).order_by('-timestamp')
        elif 'airbag' in machine_name:
            query = DAirbag.objects.filter(machine=machine).order_by('-timestamp')
        elif 'pin' in machine_name:
            query = DPinArrival.objects.filter(machine=machine).order_by('-timestamp')
        elif 'pcb' in machine_name:
            query = DPcb.objects.filter(machine=machine).order_by('-timestamp')
        else:
            return Response(f'Incorrect machine name provided for ID: {machine_id}', status=status.HTTP_400_BAD_REQUEST)

        # Filter by camera_id if provided
        if camera_id:
            query = query.filter(camera_id=camera_id)

        # Limit by 'n' if provided
        if n:
            query = query[:int(n)]

        data = query.values('id', 'camera_id', 'machine__name', 'status', 'proc_time', 'timestamp')
        return Response(list(data), status=status.HTTP_200_OK)


class MachineAnomalyDataView(APIView):
    """Retrieve only anomalies data for a given machine and camera"""

    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter(
                'machine_id',
                openapi.IN_PATH,
                description="ID of the machine to filter data",
                type=openapi.TYPE_INTEGER
            ),
            openapi.Parameter(
                'camera_id',
                openapi.IN_QUERY,
                description="(Optional) Filter by camera ID",
                type=openapi.TYPE_INTEGER,
                required=False,
            ),
            openapi.Parameter(
                'n',
                openapi.IN_QUERY,
                description="(Optional) The number of latest anomaly records to retrieve",
                type=openapi.TYPE_INTEGER,
                required=False,
                default=100
            ),
        ],
        responses={
            200: openapi.Schema(type=openapi.TYPE_ARRAY, items=openapi.Schema(type=openapi.TYPE_OBJECT, properties={
                'id': openapi.Schema(type=openapi.TYPE_INTEGER),
                'camera_id': openapi.Schema(type=openapi.TYPE_INTEGER),
                'machine': openapi.Schema(type=openapi.TYPE_STRING),
                'status': openapi.Schema(type=openapi.TYPE_STRING),
                'proc_time': openapi.Schema(type=openapi.TYPE_STRING),
                'timestamp': openapi.Schema(type=openapi.TYPE_STRING),
            }))
        }
    )
    def get(self, request, machine_id):
        n = request.query_params.get('n', 100)
        camera_id = request.query_params.get('camera_id', None)

        if not machine_id:
            return Response({'error': 'Providing the "machine_id" is required.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Fetch the machine
            machine = Machine.objects.get(id=machine_id)
            machine_name = machine.name.lower()
        except Machine.DoesNotExist:
            return Response({'error': 'Machine not found.'}, status=status.HTTP_404_NOT_FOUND)

        # Determine the appropriate model based on the machine name
        query = None
        if 'mold' in machine_name:
            query = DMold.objects.filter(status='NG', machine=machine).order_by('-timestamp')
        elif 'reel' in machine_name:
            query = DReelPackaging.objects.filter(status='NG', machine=machine).order_by('-timestamp')
        elif 'airbag' in machine_name:
            query = DAirbag.objects.filter(status='NG', machine=machine).order_by('-timestamp')
        elif 'pin' in machine_name:
            query = DPinArrival.objects.filter(status='NG', machine=machine).order_by('-timestamp')
        elif 'pcb' in machine_name:
            query = DPcb.objects.filter(status='NG', machine=machine).order_by('-timestamp')
        else:
            return Response(f'Incorrect machine name provided for ID: {machine_id}', status=status.HTTP_400_BAD_REQUEST)

        # Filter by camera_id if provided
        if camera_id:
            query = query.filter(camera_id=camera_id)

        # Limit by 'n' if provided
        if n:
            query = query[:int(n)]

        data = query.values('id', 'camera_id', 'machine__name', 'status', 'proc_time', 'timestamp')
        return Response(list(data), status=status.HTTP_200_OK)


class DataCountView(APIView):
    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter(
                'machine_id',
                openapi.IN_QUERY,
                description="(Optional) Filter by machine ID",
                type=openapi.TYPE_INTEGER,
                required=False,
            ),
            openapi.Parameter(
                'camera_id',
                openapi.IN_QUERY,
                description="(Optional) Filter by camera ID",
                type=openapi.TYPE_INTEGER,
                required=False
            ),
        ],
        responses={
            200: openapi.Response(
                description="Camera data fetched successfully",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'detection_count': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'anomaly_count': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'camera_count': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'machine_count': openapi.Schema(type=openapi.TYPE_INTEGER),
                    }
                )
            ),
            400: 'Bad Request',
            500: 'Internal Server Error',
        }
    )
    def get(self, request):
        machine_id = request.query_params.get('machine_id', None)
        camera_id = request.query_params.get('camera_id', None)
        logger.info(f"Fetching data for machine ID {machine_id} with optional camera ID '{camera_id}'")

        detection_count = 0
        anomaly_count = 0
        camera_count = 0
        camera_data_response = {
            'detection_count': detection_count,
            'anomaly_count': anomaly_count,
            'camera_count': camera_count,
            'machine_count': 1,
        }
        try:
            # Define the model classes for handling different machine data
            model_classes = {
                'airbag': DAirbag,
                'mold': DMold,
                'pcb': DPcb,
                'pin': DPinArrival,
                'reel-packaging': DReelPackaging,
            }
            # Fetch the machine to determine the type

            if machine_id is not None:
                try:
                    machine = Machine.objects.get(id=machine_id)
                    machine_name = machine.name.lower()  # Use the name to determine the model
                    # logger.info(f"Machine details: ID {machine_id}, Name: {machine_name}")
                except Machine.DoesNotExist:
                    logger.error(f"Machine with ID {machine_id} does not exist.")
                    return Response({'status': 'error', 'message': 'Machine not found'},
                                    status=status.HTTP_400_BAD_REQUEST)

                # Determine the model class based on machine name
                query = None
                for key, value in model_classes.items():
                    if key in machine_name:
                        query = value
                        break

                if not query:
                    logger.error(f"No data model found for machine name: {machine_name}")
                    return Response({'status': 'error', 'message': f'No data model found for machine ID: {machine_id}'},
                                    status=status.HTTP_400_BAD_REQUEST)

                # Prepare filter parameters
                filter_params = {'machine_id': machine_id}
                if camera_id:
                    filter_params['camera_id'] = camera_id

                # Fetch data based on machine_id and optional camera_id
                machine_data = query.objects.filter(**filter_params)
                if not machine_data.exists():
                    logger.warning(f"No data found for filter parameters: {filter_params}")
                    return Response(
                        {'status': 'error', 'message': f'No data exists for filtered parameters: {filter_params}'},
                        status=status.HTTP_400_BAD_REQUEST)

                # Process the data to count detections and anomalies
                for entry in machine_data:
                    # logger.info(f"Processing entry: {entry.id}, Status: {entry.status}")
                    status_values = entry.status.split(', ')
                    for val in status_values:
                        if val == 'NG':
                            anomaly_count += 1
                        detection_count += 1

                camera_count = Camera.objects.filter(machine_id=machine_id).count()
                camera_data_response['camera_count'] = camera_count
                camera_data_response['detection_count'] = detection_count
                camera_data_response['anomaly_count'] = anomaly_count
                # logger.info(f"Data fetched successfully for machine ID '{machine_id}': {camera_data_response}")
            else:

                query_list = [DMold.objects, DReelPackaging.objects, DAirbag.objects, DPinArrival.objects, DPcb.objects]

                for query in query_list:
                    count_normal = query.filter(status='Normal').count()
                    count_norm = query.count()
                    count_anomal = query.filter(status='NG').count()
                    logger.info(f'\n\nobjects: {count_norm}, normal: {count_normal}, abnormal: {count_anomal}\n')
                    detection_count += count_normal
                    anomaly_count += count_anomal

                camera_count = Camera.objects.count()
                machine_count = Machine.objects.count()
                camera_data_response['machine_count'] = machine_count
                camera_data_response['camera_count'] = camera_count
                camera_data_response['detection_count'] = detection_count
                camera_data_response['anomaly_count'] = anomaly_count

            return Response(camera_data_response, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"An unexpected error occurred while fetching data: {str(e)}")
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class DAirbagView(APIView):
    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'camera_id': openapi.Schema(type=openapi.TYPE_INTEGER),
                'machine_name': openapi.Schema(type=openapi.TYPE_STRING),
                'status': openapi.Schema(type=openapi.TYPE_STRING),
                # 'fbc': openapi.Schema(type=openapi.TYPE_STRING),
                'proc_time': openapi.Schema(type=openapi.TYPE_STRING),
                'timestamp': openapi.Schema(type=openapi.TYPE_STRING),

            },
        ),
        responses={201: 'Data saved successfully', 500: 'Error'},
    )
    def post(self, request):
        try:
            data = request.data
            camera_id = data.get('camera_id')
            machine_name = data.get('machine_name')
            status_str = data.get('status')

            proc_time = data.get('proc_time')
            timestamp_str = data.get('timestamp')

            # Parse timestamp
            # timestamp = datetime.strptime(timestamp_str, '%Y-%m-%dT%H:%M:%S.%fZ').replace(tzinfo=pytz.UTC)
            timestamp = datetime.strptime(timestamp_str, '%m/%d/%Y, %I:%M:%S %p')
            tz = pytz.timezone('Asia/Seoul')
            timestamp = tz.localize(timestamp)
            # Find the camera
            try:
                # Find the machine
                machine = Machine.objects.get(name=machine_name)
                # Find the Camera
                camera = Camera.objects.filter(ref_id=camera_id, machine=machine).first()
                if camera is None or machine is None:
                    return Response({'status': 'error',
                                     'message': f"Camera(camera_id={camera_id}) or machine(machine_name={machine_name}) not found."},
                                    status=status.HTTP_404_NOT_FOUND)
                DAirbag.objects.create(
                    camera=camera,
                    machine=machine,
                    status=status_str,
                    proc_time=proc_time,
                    timestamp=timestamp,
                    # fbc=data.get('fbc')
                )
            except Camera.DoesNotExist as e:
                logger.error(f"[DAirbag create] Error getting camera or machine: {camera_id}. Exception: {e}")
                return Response({'status': 'error', 'message': 'Camera not found.'}, status=status.HTTP_404_NOT_FOUND)
            except Machine.DoesNotExist as e:
                logger.error(f"[DAirbag create] Error getting camera or machine: {camera_id}. Exception: {e}")
                return Response({'status': 'error', 'message': 'Machine not found.'}, status=status.HTTP_404_NOT_FOUND)

            return Response({'status': 'success', 'message': 'Data saved successfully'}, status=status.HTTP_201_CREATED)

        except Exception as e:
            logger.error(f"Error saving data: {str(e)}")
            return Response({'status': 'error', 'message': 'Error occurred while saving data.'},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @swagger_auto_schema(
        responses={
            200: openapi.Schema(type=openapi.TYPE_ARRAY, items=openapi.Schema(type=openapi.TYPE_OBJECT, properties={
                'id': openapi.Schema(type=openapi.TYPE_INTEGER),
                'camera_id': openapi.Schema(type=openapi.TYPE_INTEGER),
                'machine': openapi.Schema(type=openapi.TYPE_STRING),
                'status': openapi.Schema(type=openapi.TYPE_STRING),
                # 'fbc': openapi.Schema(type=openapi.TYPE_STRING),
                'proc_time': openapi.Schema(type=openapi.TYPE_STRING),
                'timestamp': openapi.Schema(type=openapi.TYPE_STRING),
            }))}
    )
    def get(self, request):
        airbags_list = DAirbag.objects.values(
            'id', 'camera_id', 'machine__name', 'status',
            'proc_time', 'timestamp'
        )
        return Response(list(airbags_list), status=status.HTTP_200_OK)


class DMoldView(APIView):
    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'camera_id': openapi.Schema(type=openapi.TYPE_INTEGER),
                'machine_name': openapi.Schema(type=openapi.TYPE_STRING),
                'status': openapi.Schema(type=openapi.TYPE_STRING),
                'proc_time': openapi.Schema(type=openapi.TYPE_STRING),
                'trigger_similarity': openapi.Schema(
                    type=openapi.TYPE_ARRAY,
                    items=openapi.Items(type=openapi.TYPE_STRING),
                    description='Array of trigger similarities',
                    min_items=2,
                ),
                'timestamp': openapi.Schema(type=openapi.TYPE_STRING),
                # 'fbc': openapi.Schema(type=openapi.TYPE_STRING),
            },
        ),
        responses={201: 'Data saved successfully', 500: 'Error'},
    )
    def post(self, request):
        try:
            data = request.data
            camera_id = data.get('camera_id')
            machine_name = data.get('machine_name')
            status_str = data.get('status')
            proc_time = data.get('proc_time')
            timestamp_str = data.get('timestamp')
            trigger_similarity = data.get('trigger_similarity')
            trigger_similarity_00 = trigger_similarity[0] if trigger_similarity and len(
                trigger_similarity) >= 2 else None
            trigger_similarity_01 = trigger_similarity[1] if trigger_similarity and len(
                trigger_similarity) >= 2 else None

            # Parse timestamp
            timestamp = datetime.strptime(timestamp_str, '%m/%d/%Y, %I:%M:%S %p')
            tz = pytz.timezone('Asia/Seoul')
            timestamp = tz.localize(timestamp)

            try:
                # Find the machine
                machine = Machine.objects.get(name=machine_name)
                # Find the Camera
                camera = Camera.objects.filter(ref_id=camera_id, machine=machine).first()
                if camera is None or machine is None:
                    return Response({'status': 'error',
                                     'message': f"Camera(camera_id={camera_id}) or machine(machine_name={machine_name}) not found."},
                                    status=status.HTTP_404_NOT_FOUND)
                DMold.objects.create(
                    camera=camera,
                    machine=machine,
                    status=status_str,
                    trigger_similarity_0=trigger_similarity_00,
                    trigger_similarity_1=trigger_similarity_01,
                    proc_time=proc_time,
                    timestamp=timestamp,
                    # fbc=data.get('fbc')
                )
            except Camera.DoesNotExist as e:
                return Response({'status': 'error', 'message': 'Camera not found.'}, status=status.HTTP_404_NOT_FOUND)
            except Machine.DoesNotExist as e:
                logger.error(f"[DAirbag create] Error getting camera or machine: {camera_id}. Exception: {e}")
                return Response({'status': 'error', 'message': 'Machine not found.'}, status=status.HTTP_404_NOT_FOUND)

            return Response({'status': 'success', 'message': 'Data saved successfully'}, status=status.HTTP_201_CREATED)

        except Exception as e:
            logger.error(f"Error saving data: {str(e)}")
            return Response({'status': 'error', 'message': 'Error occurred while saving data.'},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @swagger_auto_schema(
        responses={
            200: openapi.Schema(type=openapi.TYPE_ARRAY, items=openapi.Schema(type=openapi.TYPE_OBJECT, properties={
                'id': openapi.Schema(type=openapi.TYPE_INTEGER),
                'camera_id': openapi.Schema(type=openapi.TYPE_INTEGER),
                'machine': openapi.Schema(type=openapi.TYPE_STRING),
                'status': openapi.Schema(type=openapi.TYPE_STRING),
                'proc_time': openapi.Schema(type=openapi.TYPE_STRING),
                'timestamp': openapi.Schema(type=openapi.TYPE_STRING),
                # 'fbc': openapi.Schema(type=openapi.TYPE_STRING),
            }))}
    )
    def get(self, request):
        molds_list = DMold.objects.values('id', 'camera_id', 'machine__name', 'status', 'proc_time', 'timestamp')
        return Response(list(molds_list), status=status.HTTP_200_OK)


class DPcbView(APIView):
    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'camera_id': openapi.Schema(type=openapi.TYPE_INTEGER),
                'machine_name': openapi.Schema(type=openapi.TYPE_STRING),
                'status': openapi.Schema(type=openapi.TYPE_STRING),
                'proc_time': openapi.Schema(type=openapi.TYPE_STRING),
                'timestamp': openapi.Schema(type=openapi.TYPE_STRING),
                # 'fbc': openapi.Schema(type=openapi.TYPE_STRING),
            },
        ),
        responses={201: 'Data saved successfully', 500: 'Error'},
    )
    def post(self, request):
        try:
            data = request.data
            camera_id = data.get('camera_id')
            machine_name = data.get('machine_name')
            status_str = data.get('status')
            proc_time = data.get('proc_time')
            timestamp_str = data.get('timestamp')

            # Parse timestamp
            timestamp = datetime.strptime(timestamp_str, '%m/%d/%Y, %I:%M:%S %p')
            tz = pytz.timezone('Asia/Seoul')
            timestamp = tz.localize(timestamp)

            try:
                # Find the machine
                machine = Machine.objects.get(name=machine_name)
                # Find the Camera
                camera = Camera.objects.filter(ref_id=camera_id, machine=machine).first()
                if camera is None or machine is None:
                    return Response({'status': 'error',
                                     'message': f"Camera(camera_id={camera_id}) or machine(machine_name={machine_name}) not found."},
                                    status=status.HTTP_404_NOT_FOUND)
                DPcb.objects.create(
                    camera=camera,
                    machine=machine,
                    status=status_str,
                    proc_time=proc_time,
                    timestamp=timestamp,
                    # fbc=data.get('fbc')
                )
            except Camera.DoesNotExist as e:
                return Response({'status': 'error', 'message': 'Camera not found.'}, status=status.HTTP_404_NOT_FOUND)
            except Machine.DoesNotExist as e:
                logger.error(f"[DAirbag create] Error getting camera or machine: {camera_id}. Exception: {e}")
                return Response({'status': 'error', 'message': 'Machine not found.'}, status=status.HTTP_404_NOT_FOUND)

            return Response({'status': 'success', 'message': 'Data saved successfully'}, status=status.HTTP_201_CREATED)

        except Exception as e:
            logger.error(f"Error saving data: {str(e)}")
            return Response({'status': 'error', 'message': 'Error occurred while saving data.'},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @swagger_auto_schema(
        responses={
            200: openapi.Schema(type=openapi.TYPE_ARRAY, items=openapi.Schema(type=openapi.TYPE_OBJECT, properties={
                'id': openapi.Schema(type=openapi.TYPE_INTEGER),
                'camera_id': openapi.Schema(type=openapi.TYPE_INTEGER),
                'machine': openapi.Schema(type=openapi.TYPE_STRING),
                'status': openapi.Schema(type=openapi.TYPE_STRING),
                'proc_time': openapi.Schema(type=openapi.TYPE_STRING),
                'timestamp': openapi.Schema(type=openapi.TYPE_STRING),
                # 'fbc': openapi.Schema(type=openapi.TYPE_STRING),
            }))}
    )
    def get(self, request):
        pcbs_list = DPcb.objects.values('id', 'camera_id', 'machine__name', 'status', 'proc_time', 'timestamp')
        return Response(list(pcbs_list), status=status.HTTP_200_OK)


class DPinArrivalView(APIView):
    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'camera_id': openapi.Schema(type=openapi.TYPE_INTEGER),
                'machine_name': openapi.Schema(type=openapi.TYPE_STRING),
                'status': openapi.Schema(type=openapi.TYPE_STRING),
                'proc_time': openapi.Schema(type=openapi.TYPE_STRING),
                'timestamp': openapi.Schema(type=openapi.TYPE_STRING),
                # 'fbc': openapi.Schema(type=openapi.TYPE_STRING),
            },
        ),
        responses={201: 'Data saved successfully', 500: 'Error'},
    )
    def post(self, request):
        try:
            data = request.data
            camera_id = data.get('camera_id')
            machine_name = data.get('machine_name')
            status_str = data.get('status')
            proc_time = data.get('proc_time')
            timestamp_str = data.get('timestamp')

            # Parse timestamp
            timestamp = datetime.strptime(timestamp_str, '%m/%d/%Y, %I:%M:%S %p')
            tz = pytz.timezone('Asia/Seoul')
            timestamp = tz.localize(timestamp)

            # Find the machine
            machine = Machine.objects.get(name=machine_name)
            # Find the Camera
            camera = Camera.objects.filter(ref_id=camera_id, machine=machine).first()
            if camera is None or machine is None:
                return Response({'status': 'error',
                                 'message': f"Camera(camera_id={camera_id}) or machine(machine_name={machine_name}) not found."},
                                status=status.HTTP_404_NOT_FOUND)
            DPinArrival.objects.create(
                camera=camera,
                status=status_str,
                proc_time=proc_time,
                timestamp=timestamp,
                # fbc=data.get('fbc')
            )

            return Response({'status': 'success', 'message': 'Data saved successfully'}, status=status.HTTP_201_CREATED)
        except Camera.DoesNotExist:
            return Response({'status': 'error', 'message': 'Camera not found.'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.error(f"Error saving data: {str(e)}")
            return Response({'status': 'error', 'message': 'Error occurred while saving data.'},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @swagger_auto_schema(
        responses={
            200: openapi.Schema(type=openapi.TYPE_ARRAY, items=openapi.Schema(type=openapi.TYPE_OBJECT, properties={
                'id': openapi.Schema(type=openapi.TYPE_INTEGER),
                'camera_id': openapi.Schema(type=openapi.TYPE_INTEGER),
                'machine': openapi.Schema(type=openapi.TYPE_STRING),
                'status': openapi.Schema(type=openapi.TYPE_STRING),
                'proc_time': openapi.Schema(type=openapi.TYPE_STRING),
                'timestamp': openapi.Schema(type=openapi.TYPE_STRING),
                # 'fbc': openapi.Schema(type=openapi.TYPE_STRING),
            }))}
    )
    def get(self, request):
        pin_arrivals_list = DPinArrival.objects.values('id', 'camera_id', 'machine__name', 'status', 'proc_time',
                                                       'timestamp')
        return Response(list(pin_arrivals_list), status=status.HTTP_200_OK)


class DReelPackagingView(APIView):
    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'camera_id': openapi.Schema(type=openapi.TYPE_INTEGER),
                'machine_name': openapi.Schema(type=openapi.TYPE_STRING),
                'status': openapi.Schema(type=openapi.TYPE_STRING),
                'proc_time': openapi.Schema(type=openapi.TYPE_STRING),
                'timestamp': openapi.Schema(type=openapi.TYPE_STRING),
                # 'fbc': openapi.Schema(type=openapi.TYPE_STRING),
            },
        ),
        responses={201: 'Data saved successfully', 500: 'Error'},
    )
    def post(self, request):
        try:
            data = request.data
            camera_id = data.get('camera_id')
            machine_name = data.get('machine_name')
            status_str = data.get('status')
            proc_time = data.get('proc_time')
            timestamp_str = data.get('timestamp')

            # Parse timestamp
            timestamp = datetime.strptime(timestamp_str, '%m/%d/%Y, %I:%M:%S %p')
            tz = pytz.timezone('Asia/Seoul')
            timestamp = tz.localize(timestamp)

            # Find the machine
            machine = Machine.objects.get(name=machine_name)
            # Find the Camera
            camera = Camera.objects.filter(ref_id=camera_id, machine=machine).first()
            if camera is None or machine is None:
                return Response({'status': 'error',
                                 'message': f"Camera(camera_id={camera_id}) or machine(machine_name={machine_name}) not found."},
                                status=status.HTTP_404_NOT_FOUND)
            DReelPackaging.objects.create(
                camera=camera,
                machine=machine,
                status=status_str,
                proc_time=proc_time,
                timestamp=timestamp,
                # fbc=data.get('fbc')
            )

            return Response({'status': 'success', 'message': 'Data saved successfully'}, status=status.HTTP_201_CREATED)
        except Camera.DoesNotExist:
            return Response({'status': 'error', 'message': 'Camera not found.'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.error(f"Error saving data: {str(e)}")
            return Response({'status': 'error', 'message': 'Error occurred while saving data.'},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @swagger_auto_schema(
        responses={
            200: openapi.Schema(type=openapi.TYPE_ARRAY, items=openapi.Schema(type=openapi.TYPE_OBJECT, properties={
                'id': openapi.Schema(type=openapi.TYPE_INTEGER),
                'camera_id': openapi.Schema(type=openapi.TYPE_INTEGER),
                'machine': openapi.Schema(type=openapi.TYPE_STRING),
                'status': openapi.Schema(type=openapi.TYPE_STRING),
                'proc_time': openapi.Schema(type=openapi.TYPE_STRING),
                'timestamp': openapi.Schema(type=openapi.TYPE_STRING),
                # 'fbc': openapi.Schema(type=openapi.TYPE_STRING),
            }))}
    )
    def get(self, request):
        reel_packagings_list = DReelPackaging.objects.values('id', 'camera_id', 'machine__name', 'status', 'proc_time',
                                                             'timestamp')
        return Response(list(reel_packagings_list), status=status.HTTP_200_OK)
