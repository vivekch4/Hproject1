def content_security_policy(get_response):
    def middleware(request):
        response = get_response(request)
        response['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
            "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
            "font-src 'self' https://cdnjs.cloudflare.com https://fonts.gstatic.com; "
            "img-src 'self' data:; "
            "frame-src 'self' https://drive.google.com; "
"media-src 'self' https://drive.google.com; "
        )
        return response
    return middleware