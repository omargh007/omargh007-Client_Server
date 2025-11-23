#done By Omar
# urls.py

#ALL templates done by Omar


from django.urls import path
from . import views
from django.contrib.auth import views as auth_views

urlpatterns = [
    path('', views.home, name='Home'),
    path('list/', views.list_files, name='list_files'),
    path('upload/', views.upload_file, name='upload_file'),
    path('download/<str:filename>/', views.download_file, name='download_file'),
    path('delete/<str:filename>/', views.delete_file, name='delete_file'),
    path('help/', views.help_view, name='Help'),
    path('register/', views.register, name='register'),
    
    # Update the logout to first close the connection
    path('logout-connection/', views.logout_connection, name='logout_connection'),
    path('login/', auth_views.LoginView.as_view(template_name='client_app/login.html' , next_page='/'), name='login'),
    path('logout/', views.logout_connection, name='logout'),
]