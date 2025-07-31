# debug_logging_middleware.py
import logging

logger = logging.getLogger('django.request')

class DebugLoggingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Log the incoming request
        print(f"🔍 [MIDDLEWARE] {request.method} {request.path}")
        print(f"🔍 [MIDDLEWARE] Headers: {dict(request.headers)}")
        print(f"🔍 [MIDDLEWARE] User: {request.user if hasattr(request, 'user') else 'No user'}")
        
        if request.method == 'POST':
            print(f"🔍 [MIDDLEWARE] POST data: {request.POST}")
            # For JSON data, you might need to read the body
            try:
                if hasattr(request, 'body') and request.body:
                    print(f"🔍 [MIDDLEWARE] Request body: {request.body.decode('utf-8')}")
            except:
                print("🔍 [MIDDLEWARE] Could not decode request body")

        response = self.get_response(request)
        
        print(f"🔍 [MIDDLEWARE] Response status: {response.status_code}")
        return response