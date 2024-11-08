from django.contrib import admin
from .models import *


class CustomUserAdmin(admin.ModelAdmin):
    list_display = ('id', 'username', 'password', 'name', 'email', 'is_activated', 'is_superuser', 'created_at', 'updated_at', 'approved_by', 'updated_by', 'is_deleted', 'factory_list')
    def factory_list(self, obj):
        return ", ".join([factory.name for factory in obj.factories.all()])
    factory_list.short_description = "Factories"
    list_filter = ('is_superuser', 'is_staff', 'is_activated', 'created_at', 'updated_at', 'is_deleted', 'factories')
    search_fields = ('username', 'name', 'email', 'factories')
    readonly_fields = ('created_at', 'updated_at', 'approved_by', 'updated_by')

    def save_model(self, request, obj, form, change):
        # If the user is being changed (not created)
        if change:
            # Set updated_by to the current user
            if request.user.is_superuser and not obj.is_activated:
                obj.approved_by = request.user

        obj.updated_by = request.user
        # If it's a new user and they're not a superuser, leave approved_by as None
        if not change and not obj.is_superuser:
            obj.approved_by = None  # For new users who are non-superusers

        # Call the parent class's save_model to save the object
        super().save_model(request, obj, form, change)


class FactoryAdmin(admin.ModelAdmin):
    list_display = (
        'id', 'name', 'location', 'created_at', 'updated_at', 'is_deleted'
    )
    search_fields = ('name', 'location')  # Adjust based on your Camera model
    list_filter = ('id', 'name', 'location', 'created_at', 'updated_at', 'is_deleted')
    list_per_page = 100  # Number of items per page


class CategoryAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'description')
    search_fields = ('id', 'name', 'description')
    list_filter = ('id', 'name', 'description')
    list_per_page = 100


class MachineAdmin(admin.ModelAdmin):
    list_display = (
        'id', 'name', 'title', 'ip_address', 'location', 'category', 'factory', 'created_at', 'last_reset_time', 'updated_at', 'is_deleted'
    )
    search_fields = ('name', 'category', 'factory', 'title')  # Adjust based on your Camera model
    list_filter = ('name', 'title', 'category', 'factory', 'ip_address', 'created_at', 'updated_at', 'is_deleted')
    list_per_page = 100  # Number of items per page


class CameraAdmin(admin.ModelAdmin):
    list_display = (
        'id', 'ref_id', 'name', 'serial_no', 'machine', 'factory', 'created_at', 'updated_at', 'is_deleted'
    )
    search_fields = ('ref_id', 'name', 'machine', 'factory')  # Adjust based on your Camera model
    list_filter = ('ref_id', 'name', 'machine', 'factory', 'created_at', 'updated_at', 'is_deleted')
    list_per_page = 100  # Number of items per page


class DMoldAdmin(admin.ModelAdmin):
    list_display = (
        'id', 'status', 'trigger_similarity_0', 'trigger_similarity_1', 
        'proc_time', 'timestamp', 'camera', 'machine'
    )
    search_fields = ('status', 'camera__name', 'machine__name')  # Adjust based on your Camera model
    list_filter = ('status', 'timestamp', 'camera', 'machine')
    list_per_page = 100  # Number of items per page


class DPcbAdmin(admin.ModelAdmin):
    list_display = (
        'id', 'status', 'trigger_similarity_0', 'trigger_similarity_1', 
        'proc_time', 'timestamp', 'camera', 'machine'
    )
    search_fields = ('status', 'camera__name', 'machine')
    list_filter = ('status', 'timestamp', 'camera', 'machine')
    list_per_page = 100  # Number of items per page


class DReelPackagingAdmin(admin.ModelAdmin):
    list_display = (
        'id', 'status', 'proc_time', 'timestamp', 'camera', 'machine'
    )
    search_fields = ('status', 'camera__name', 'machine')  # Adjust based on your Camera model
    list_filter = ('status', 'timestamp', 'camera', 'machine')
    list_per_page = 100  # Number of items per page


class DPinArrivalAdmin(admin.ModelAdmin):
    list_display = (
        'id', 'status', 'proc_time', 'timestamp', 'camera', 'machine'
    )
    search_fields = ('status', 'camera__name', 'machine')  # Adjust based on your Camera model
    list_filter = ('status', 'timestamp', 'camera', 'machine')
    list_per_page = 100  # Number of items per page


class DAirbagAdmin(admin.ModelAdmin):
    list_display = (
        'id', 'status', 'proc_time', 'timestamp', 'camera', 'machine'
    )
    search_fields = ('status', 'camera__name', 'machine')  # Adjust based on your Camera model
    list_filter = ('status', 'timestamp', 'camera', 'machine')
    list_per_page = 100  # Number of items per page


# Registering other models
admin.site.register(User, CustomUserAdmin)
admin.site.register(Factory, FactoryAdmin)
admin.site.register(Category, CategoryAdmin)
admin.site.register(Machine, MachineAdmin)
admin.site.register(Camera, CameraAdmin)
admin.site.register(DAirbag, DAirbagAdmin)
admin.site.register(DMold, DMoldAdmin)
admin.site.register(DPcb, DPcbAdmin)
admin.site.register(DPinArrival, DPinArrivalAdmin)
admin.site.register(DReelPackaging, DReelPackagingAdmin)
