from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.core.exceptions import ValidationError
from django.db import models


# class UserManager(BaseUserManager):
#     def create_user(self, username, password, **extra_fields):
#         if not username:
#             raise ValueError("Username is required")
#         if not password:
#             raise ValueError("Password is required")

#         user = self.model(
#             username=username
#         )
#         user.set_password(password)  # Hash the password
#         user.save(using=self._db)
#         return user

#     def create_superuser(self, username, email, password, **extra_fields):
#         if not username:
#             raise ValueError("Username is required")
#         if not password:
#             raise ValueError("Password is required")
#         if not email:
#             raise ValueError("Email is required")
#         user = self.create_user(
#             username=username,
#             email=email
#         )
#         user.set_password(password)
#         user.is_superuser = True
#         user.is_activated = True
#         user.is_staff = True
#         user.save(using=self._db)
#         return user

# class User(AbstractBaseUser, PermissionsMixin):
#     id = models.AutoField(primary_key=True)
#     username = models.CharField(max_length=255, unique=True)
#     name = models.CharField(max_length=50, null=True, default='No Name')
#     password = models.CharField(max_length=255)
#     email = models.EmailField(unique=True, null=True, default=None)
#     is_superuser = models.BooleanField(default=False)
#     is_staff = models.BooleanField(default=False)
#     is_activated = models.BooleanField(default=False)
#     created_at = models.DateTimeField(auto_now_add=True)
#     updated_at = models.DateTimeField(auto_now=True)
#     approved_by = models.ForeignKey('self', null=True, blank=True, related_name='user_approved', on_delete=models.SET_NULL
#     )
#     updated_by = models.ForeignKey('self', null=True, blank=True, related_name='user_updated', on_delete=models.SET_NULL
#     )
#     last_login =  models.DateTimeField(auto_now=True)
#     factories = models.ManyToManyField('Factory', related_name='users', blank=True)
#     # machines = models.ManyToManyField('Machine', related_name='machines', blank=True)
#     is_deleted = models.BooleanField(default=False)

#     objects = UserManager()
#     USERNAME_FIELD = 'username'
#     # REQUIRED_FIELDS = ['email']

#     def __str__(self):
#         return self.username

#     def clean(self):
#         if not self.username:
#             raise ValidationError("Username cannot be blank.")
#         # if not self.email:
#         #     raise ValidationError("Email address cannot be blank.")

#     class Meta:
#         db_table = 'users'
#         indexes = [
#             models.Index(fields=['username','is_deleted']),
#         ]

class UserManager(BaseUserManager):
    def create_user(self, username, password, email=None, **extra_fields):
        if not username:
            raise ValueError("Username is required")
        if not password:
            raise ValueError("Password is required")

        user = self.model(username=username, email=email)
        user.set_password(password)  # Hash the password
        user.save(using=self._db)
        return user

    def create_superuser(self, username, email, password, **extra_fields):
        if not username:
            raise ValueError("Username is required")
        if not password:
            raise ValueError("Password is required")
        if not email:
            raise ValueError("Email is required")
        user = self.create_user(username=username, email=email, password=password, **extra_fields)
        user.is_superuser = True
        user.is_activated = True
        user.is_staff = True
        user.save(using=self._db)
        return user

class User(AbstractBaseUser, PermissionsMixin):
    id = models.AutoField(primary_key=True)
    username = models.CharField(max_length=255, unique=True)
    name = models.CharField(max_length=50, null=True, default='No Name')
    password = models.CharField(max_length=255)
    email = models.EmailField(unique=True, null=False, blank=False)  # Make email required
    is_superuser = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    is_activated = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    approved_by = models.ForeignKey('self', null=True, blank=True, related_name='user_approved', on_delete=models.SET_NULL)
    updated_by = models.ForeignKey('self', null=True, blank=True, related_name='user_updated', on_delete=models.SET_NULL)
    last_login = models.DateTimeField(auto_now=True)
    factories = models.ManyToManyField('Factory', related_name='users', blank=True)
    is_deleted = models.BooleanField(default=False)

    objects = UserManager()

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email']

    def __str__(self):
        return self.username

    def clean(self):
        if not self.username:
            raise ValidationError("Username cannot be blank.")
        if not self.email:
            raise ValidationError("Email address cannot be blank.")

    class Meta:
        db_table = 'users'
        indexes = [
            models.Index(fields=['username', 'is_deleted']),
        ]
        ordering = ['username']



# Factory Model 
class Factory(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=255)
    location = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_deleted = models.BooleanField(default=False)

    def __str__(self):
        return self.name

    class Meta:
        db_table = 'factories'
        verbose_name = 'Factory'
        verbose_name_plural = 'Factories'
        indexes = [
            models.Index(fields=['name', 'is_deleted']),
        ]

# Machine Category model
class Category(models.Model):
    name = models.CharField(max_length=50, unique=True)
    description = models.TextField(null=True, blank=True)

    def __str__(self):
        return self.name
    class Meta:
        db_table = 'categories'
        verbose_name = 'Category'
        verbose_name_plural = 'Categories'
        ordering = ['name']

# Machine Model 
class Machine(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=255, unique=True)
    title = models.CharField(max_length=255)
    ip_address = models.CharField(max_length=15)
    location = models.CharField(max_length=255)
    category = models.ForeignKey(Category, on_delete=models.SET_NULL, related_name="machine_category", null=True)
    factory = models.ForeignKey(Factory, on_delete=models.CASCADE, related_name='machine_factory')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_deleted = models.BooleanField(default=False)
    
    # New fields to track reset time and category 
    last_reset_time = models.DateTimeField(null=True, blank=True) 
    last_reset_category = models.CharField(max_length=50, null=True, blank=True)
    # last_reset_machine_id = models.IntegerField(null=True, blank=True)
    # last_reset_machine = models.CharField(max_length=255, null=True, blank=True)  # New field
    last_reset_machine = models.CharField(max_length=255, null=True, blank=True)  # New field



    def __str__(self):
        return self.name
    
    class Meta:
        db_table = 'machines'
        indexes = [
            models.Index(fields=['name', 'factory', 'is_deleted', 'category']),
        ]

class Camera(models.Model):
    id = models.AutoField(primary_key=True)
    ref_id = models.IntegerField(null=True, blank=True)
    name = models.CharField(max_length=255)
    serial_no = models.IntegerField(null=True, blank=True)
    machine = models.ForeignKey(Machine, on_delete=models.CASCADE, related_name='cameras')
    factory = models.ForeignKey(Factory, on_delete=models.CASCADE, related_name="factory_cameras", null=True, default=None)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_deleted = models.BooleanField(default=False)
    
    def __str__(self):
        return self.name
    
    class Meta:
        db_table = 'cameras'
        indexes = [
            models.Index(fields=['machine','is_deleted', 'factory']),
        ]

# Mold Machine Model 
class DMold(models.Model):
    id = models.AutoField(primary_key=True)
    status = models.CharField(max_length=255)
    # fbc = models.FloatField(null=True, blank=True) not required
    # Trigger
    trigger_similarity_0 = models.FloatField(null=True, blank=True)
    trigger_similarity_1 = models.FloatField(null=True, blank=True)
    # Detections 
    # detections_0 = models.JSONField(null=True, blank=True)  not required
    # detections_1 = models.JSONField(null=True, blank=True)  not required
    proc_time = models.FloatField(null=True, blank=True)  
    timestamp = models.DateTimeField(auto_now_add=True)
    camera = models.ForeignKey(Camera, on_delete=models.CASCADE, related_name='mold_camera_parameter')
    machine = models.ForeignKey(Machine, on_delete=models.CASCADE, related_name='mold_machine_parameter')
    class Meta:
        db_table = 'd_mold'
        verbose_name = 'Mold'
        verbose_name_plural = 'Mold data'
        indexes = [
            models.Index(fields=['machine','camera','timestamp','status']),
        ]

# Pin Arrival Model 
class DPinArrival(models.Model):
    id = models.AutoField(primary_key=True)
    status = models.CharField(max_length=255)
    proc_time = models.CharField(max_length=255, null=True)
    # fbc = models.FloatField(null=True, blank=True) not required
    timestamp = models.DateTimeField(auto_now_add=True)
    camera = models.ForeignKey(Camera, on_delete=models.CASCADE, related_name='pin_arrival_camera_parameter')
    machine = models.ForeignKey(Machine, on_delete=models.CASCADE, related_name='pin_arrival_machine_parameter')
    class Meta:
        db_table = 'd_pin_arrival'  
        verbose_name = 'Pin arrival'
        verbose_name_plural = 'Pin arrival data'
        indexes = [
            models.Index(fields=['machine','camera','timestamp','status']),
        ]

# Airbag Model 
class DAirbag(models.Model):
    id = models.AutoField(primary_key=True)
    status = models.CharField(max_length=255)
    # fbc = models.FloatField(null=True, blank=True) not required
    proc_time = models.FloatField(null=True, blank=True)  
    timestamp = models.DateTimeField(auto_now_add=True)
    camera = models.ForeignKey(Camera, on_delete=models.CASCADE, related_name='airbag_camera_parameters')
    machine = models.ForeignKey(Machine, on_delete=models.CASCADE, related_name='airbag_machine_parameters')
    
    class Meta:
        db_table = 'd_airbag'  
        verbose_name = 'Airbag'
        verbose_name_plural = 'Airbag data'
        indexes = [
            models.Index(fields=['machine','camera','timestamp','status']),
        ]

# Reel Packaging Model 
class DReelPackaging(models.Model):
    id = models.AutoField(primary_key=True)
    status = models.CharField(max_length=255)
    # fbc = models.FloatField(null=True, blank=True) not required
    proc_time = models.FloatField(null=True, blank=True)  
    timestamp = models.DateTimeField(auto_now_add=True)
    # ng_time = models.DateTimeField(auto_now_add=True) not required
    camera = models.ForeignKey(Camera, on_delete=models.CASCADE, related_name='reel_packaging_camera_parameters')
    machine = models.ForeignKey(Machine, on_delete=models.CASCADE, related_name='reel_packaging_machine_parameter')

    class Meta:
        db_table = 'd_reel_packaging'  
        verbose_name = 'Reel packaging'
        verbose_name_plural = 'Reel packaging data'
        indexes = [
            models.Index(fields=['machine','camera','timestamp','status']),
        ]

# PCB Model 
class DPcb(models.Model):
    id = models.AutoField(primary_key=True)
    status = models.CharField(max_length=255)
    # fbc = models.FloatField(null=True, blank=True) not required
    # Trigger
    trigger_similarity_0 = models.FloatField(null=True, blank=True)
    trigger_similarity_1 = models.FloatField(null=True, blank=True)
    proc_time = models.FloatField(null=True, blank=True)  
    timestamp = models.DateTimeField(auto_now_add=True)
    camera = models.ForeignKey(Camera, on_delete=models.CASCADE, related_name='pcb_camera_parameters')
    machine = models.ForeignKey(Machine, on_delete=models.CASCADE, related_name='pcb_machine_parameter_machine')

    class Meta:
        db_table = 'd_pcb'  
        verbose_name = 'PCB'
        verbose_name_plural = 'PCB data'
        indexes = [
            models.Index(fields=['machine','camera','timestamp','status']),
        ]

# MQTT Server state (AVAIL/BUSY)
class MqttClientState(models.Model):
    status = models.CharField(max_length=5)
    last_updated = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.status

    class Meta:
        db_table = 'mqtt_client_state'    
