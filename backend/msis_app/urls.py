from django.urls import path

from .views import *

baseAPI = 'api/v1'

urlpatterns = [
    path(f'{baseAPI}/auth/signup', RegisterView.as_view(), name='signup'),
    path(f'{baseAPI}/auth/login', LoginView.as_view(), name='login'),
    path(f'{baseAPI}/auth/token/refresh', CustomTokenObtainPairView.as_view(), name='token-refresh'),
    path(f'{baseAPI}/auth/find-username', FindUsernameView.as_view(), name='find-username'),
    path(f'{baseAPI}/auth/password-reset', PasswordResetRequestView.as_view(), name='password-reset-request'),
    path(f'{baseAPI}/auth/password-reset/confirm', PasswordResetView.as_view(), name='password-reset-confirm'),
    path(f'{baseAPI}/auth/users', UserView.as_view(), name='get-users'),
    path(f'{baseAPI}/auth/users/<str:user_id>', UserDetailView.as_view(), name='get-change-one-users'),

    path(f'{baseAPI}/factories', FactoryView.as_view(), name='factories'),
    path(f'{baseAPI}/factories/<str:factory_id>', FactoryDetailView.as_view(), name='get-change-factory-details'),
    path(f'{baseAPI}/factories/name-id/', FactoryNameIdView.as_view(), name='factory-name-id'), # New API path

    path(f'{baseAPI}/categories', CategoryView.as_view(), name='categories-list'),
    path(f'{baseAPI}/categories/<int:category_id>', CategoryDetailView.as_view(), name='category-detail'),
    path(f'{baseAPI}/machines', MachineView.as_view(), name='machines'),
    path(f'{baseAPI}/machines/<str:machine_id>', MachineDetailsView.as_view(), name='get-change-machine-details'),
    path(f'{baseAPI}/machines/reset/counts', MachineNgCountResetView.as_view(), name='machines'),
    path(f'{baseAPI}/cameras', CameraView.as_view(), name='cameras'),
    path(f'{baseAPI}/cameras/<str:camera_id>', CameraDetailsView.as_view(), name='get-change-camera-details'),

    path(f'{baseAPI}/detections/count', DataCountView.as_view(), name='detection-count'),
    path(f'{baseAPI}/detections/<str:machine_id>', MachineDataView.as_view(), name='get-detection-data'),
    path(f'{baseAPI}/anomalies/<str:machine_id>', MachineAnomalyDataView.as_view(), name='get-anomaly-data'),
    path(f'{baseAPI}/anomalies/<str:category>/<str:type>/<str:machine_id>', MachineStatsView.as_view(), name='get-anomaly-data'),

    path(f'{baseAPI}/data/mold', DMoldView.as_view(), name='d-mold'),
    path(f'{baseAPI}/data/pin_arrival', DPinArrivalView.as_view(), name='d-pin-arrival'),
    path(f'{baseAPI}/data/airbag', DAirbagView.as_view(), name='d-airbag'),
    path(f'{baseAPI}/data/pcb', DPcbView.as_view(), name='d-pcb'),
    path(f'{baseAPI}/data/reel_packaging', DReelPackagingView.as_view(), name='d-reel-packaging'),
]