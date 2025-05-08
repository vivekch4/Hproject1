from django.urls import path
from .views import *

from django.urls import path

urlpatterns = [
    path("home", home, name="home"),
    path("create/", create_checksheet, name="create_checksheet"),
    path("fill/", fill_checksheet, name="fill_checksheet"),
    path("fill/<int:checksheet_id>/", fill_checksheet, name="fill_checksheet_detail"),
    path("all-checksheets/", all_checksheets, name="all_checksheets"),
    path("update/<int:checksheet_id>/", update_checksheet, name="update_checksheet"),
    path("add-zone/<int:checksheet_id>/", add_zone, name="add_zone"),
    path("", login_view, name="login"),
    path("logout/", logout_view, name="logout"),
    path("create-user/", create_user, name="create_user"),
    path(
        "quality-incharge-dashboard/",
        quality_incharge_dashboard,
        name="quality_incharge_dashboard",
    ),
    path(
        "shift-incharge-dashboard/",
        shift_incharge_dashboard,
        name="shift_incharge_dashboard",
    ),
    path("operator-dashboard/", operator_dashboard, name="operator_dashboard"),
    path("users/", user_list, name="user_list"),
    path("users/edit/<int:user_id>/", edit_user, name="edit_user"),
    path("upload-poc/", upload_poc, name="upload_poc"),
    path("view-poc/", view_poc, name="view_poc"),
    path("create_startersheet/", create_startersheet, name="create_startersheet"),
    path(
        "fill_starter_sheet/<int:startersheet_id>/",
        fill_starter_sheet,
        name="fill_starter_sheet",
    ),
    path("all_startersheet/", all_startersheet, name="all_startersheet"),
    path(
        "update_startersheet/<int:startersheet_id>/",
        update_startersheet,
        name="update_startersheet",
    ),
    path(
        "Add_start_zone/<int:startersheet_id>/", Add_start_zone, name="Add_start_zone"
    ),
    path("acknowledgment/", acknowledgment_list, name="acknowledgment_list"),
    path(
        "view-filled/<int:startersheet_id>/<int:user_id>/<str:shift>/<int:id>/",
        view_filled_startersheet,
        name="view_filled_startersheet",
    ),
    path("reset-password/", reset_password, name="reset_password"),
    path("assign-sheets/<int:user_id>/", assign_sheets, name="assign_sheets"),
    path("report/", report_view, name="report"),
    path("get_today_checksheets/", get_today_checksheets, name="get_today_checksheets"),
    path(
        "request-password-reset/", request_password_reset, name="request_password_reset"
    ),
    path(
        "admin/approve-password-reset/<int:request_id>/",
        approve_password_reset,
        name="approve_password_reset",
    ),
    path(
        "admin/password-requests/",
        admin_password_requests,
        name="admin_password_requests",
    ),
    path("manage-access/", manage_access, name="manage_access"),
    path(
        "delete_checksheet/<int:checksheet_id>/",
        delete_checksheet,
        name="delete_checksheet",
    ),
    path(
        "pending_acknowledgments_check/",
        pending_acknowledgments_check,
        name="pending_acknowledgments_check",
    ),
    path("acknowledge/", acknowledge_checksheets, name="acknowledge_checksheets"),
    path("assign_poc_bulk/", assign_poc_bulk, name="assign_poc_bulk"),
    path("form-request/", form_request_view, name="form_request"),
    path("accept-request/<int:request_id>/", accept_request, name="accept_request"),
    path("reject-request/<int:request_id>/", reject_request, name="reject_request"),
    path(
        "fill_checksheet_request/<int:request_id>/",
        fill_checksheet_request,
        name="fill_checksheet_request",
    ),
    path("delete_poc/<int:poc_id>/", delete_poc, name="delete_poc"),
    path(
        "assign-users/<str:sheet_type>/<int:sheet_id>/",
        assign_users,
        name="assign_users",
    ),
    path("get_chart_data/", get_chart_data, name="get_chart_data"),
    path("get_pie_chart_data/", get_pie_chart_data, name="get_pie_chart_data"),
    path("mark_poc_as_read/", mark_poc_as_read, name="mark_poc_as_read"),
    path(
        "get_checksheet_images/",
        get_checksheet_images,
        name="get_checksheet_images",
    ),
    path("send_acknowledgments/", send_acknowledgments, name="send_acknowledgments"),
    path("approve_startersheet/", approve_startersheet, name="approve_startersheet"),
    path(
        "assign-approver/<str:model_type>/<int:pk>/<str:level>/",
        assign_approver,
        name="assign_approver",
    ),
    path(
        "toggle-level3-approval/<str:model_type>/<int:pk>/",
        toggle_level3_approval,
        name="toggle_level3_approval",
    ),
    path(
        "get_checksheet_approval_hierarchy/",
        get_checksheet_approval_hierarchy,
        name="get_checksheet_approval_hierarchy",
    ),
    path(
        "api/update-checksheet-errors/",
        update_checksheet_errors,
        name="update_checksheet_errors",
    ),
    path("api/get-checksheet-data/", get_checksheet_data, name="get_checksheet_data"),
    path("shiftpage/", shiftpage, name="shiftpage"),
    path("setting_view/", setting_view, name="setting_view"),
    path(
        "api/get-checksheets-by-line/",
        get_checksheets_by_line,
        name="get_checksheets_by_line",
    ),
    path("api/get-all-checksheets/", get_all_checksheets, name="get_all_checksheets"),
    path("accounts/login/", redirect_to_login),
    path(
        "rejection_alert_config/", rejection_alert_config, name="rejection_alert_config"
    ),
    path("get-shift-data/", get_shift_data, name="get-shift-data"),
    path("verify-shift-change/", verify_shift_change, name="verify-shift-change"),
]
