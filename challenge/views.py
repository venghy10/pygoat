from django.http import JsonResponse
from django.shortcuts import redirect, render
from django.views.generic import View
import subprocess
import re
from .utility import get_free_port
from .models import Challenge, UserChallenge


def is_valid_docker_image(image):
    # Solo permite: letras, números, guiones, puntos, barras, dos puntos (para tags)
    return re.fullmatch(r'^[a-z0-9._/-]+(:[a-zA-Z0-9._-]+)?$', image) is not None


def is_valid_container_id(cid):
    # Docker container IDs son hexadecimales de 12 a 64 caracteres
    return re.fullmatch(r'^[a-f0-9]{12,64}$', cid) is not None


def is_valid_port(port):
    return isinstance(port, int) and 1 <= port <= 65535


class DoItFast(View):
    def get(self, request, challenge):
        if not request.user.is_authenticated:
            return redirect('login')
        
        try:
            chal = Challenge.objects.get(name=challenge)
        except Exception:
            return render(request, 'chal-not-found.html')

        try:
            user_chal = UserChallenge.objects.get(user=request.user, challenge=chal)
            return render(request, 'challenge.html', {'chal': chal, 'user_chal': user_chal})
        except:
            return render(request, 'challenge.html', {'chal': chal, 'user_chal': None})
    
    def post(self, request, challenge):
        if not request.user.is_authenticated:
            return redirect('login')
        
        try:
            chal = Challenge.objects.get(name=challenge)
        except Exception:
            return render(request, 'chal-not-found.html')

        # 🔒 MITIGACIÓN 2: Validación estricta (CWE-78)
        if not is_valid_port(chal.docker_port):
            return JsonResponse({'message': 'Invalid docker port', 'status': '400'})
        if not is_valid_docker_image(chal.docker_image):
            return JsonResponse({'message': 'Invalid docker image', 'status': '400'})

        try:
            user_chal = UserChallenge.objects.get(user=request.user, challenge=chal)
            if user_chal.is_live:
                return JsonResponse({
                    'message': 'already running',
                    'status': '200',
                    'endpoint': f'http://localhost:{user_chal.port}'
                })
        except UserChallenge.DoesNotExist:
            pass

        port = get_free_port(8000, 8100)
        if port is None:
            return JsonResponse({'message': 'No free ports', 'status': '500'})

        # 🔒 MITIGACIÓN 1: Lista de argumentos (no cadena ni split)
        command = ["docker","run","-d","-p", f"{port}:{chal.docker_port}",chal.docker_image]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = process.communicate()
        container_id = output.decode('utf-8').strip()

        if not container_id or not is_valid_container_id(container_id):
            return JsonResponse({'message': 'Docker failed to start', 'status': '500'})

        # Guardar o actualizar
        user_chal, created = UserChallenge.objects.update_or_create(
            user=request.user,
            challenge=chal,
            defaults={
                'container_id': container_id,
                'port': port,
                'is_live': True
            }
        )

        return JsonResponse({
            'message': 'success',
            'status': '200',
            'endpoint': f'http://localhost:{port}'
        })

    def delete(self, request, challenge):
        if not request.user.is_authenticated:
            return redirect('login')
    
        try:
            chal = Challenge.objects.get(name=challenge)
            user_chal = UserChallenge.objects.get(user=request.user, challenge=chal)
        except Exception:
            return JsonResponse({'message': 'Not found', 'status': '404'})

        # 🔒 Validar container_id antes de usarlo
        if not is_valid_container_id(user_chal.container_id):
            return JsonResponse({'message': 'Invalid container ID', 'status': '400'})

        user_chal.is_live = False
        user_chal.save()

        # 🔒 Lista segura
        command = ["docker", "stop", user_chal.container_id]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        process.communicate()

        return JsonResponse({'message': 'success', 'status': '200'})
    
    def put(self, request, challenge):  # Corregido typo
        return JsonResponse({'message': 'not implemented', 'status': '501'})