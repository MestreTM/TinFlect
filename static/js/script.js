// static/js/script.js
document.addEventListener('DOMContentLoaded', function() {
    console.log('script.js carregado com sucesso');

    // Elementos DOM
    const dateTimeElement = document.getElementById('datetime');
    const tooltipTriggerList = document.querySelectorAll('[data-bs-toggle="tooltip"]');
    const popoverTriggerList = document.querySelectorAll('[data-bs-toggle="popover"]');
    
    // Atualizar datetime se o elemento existir
    if (dateTimeElement) {
        function updateDateTime() {
            const now = new Date();
            const options = {
                year: 'numeric',
                month: 'long',
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit',
                hour12: false
            };
            dateTimeElement.textContent = now.toLocaleString('pt-BR', options);
        }
        
        updateDateTime();
        const datetimeInterval = setInterval(updateDateTime, 1000);
        
        // Limpar intervalo ao sair da página
        window.addEventListener('beforeunload', () => {
            clearInterval(datetimeInterval);
        });
    }
    
    // Inicializar tooltips se existirem
    if (tooltipTriggerList.length > 0 && typeof bootstrap.Tooltip !== 'undefined') {
        tooltipTriggerList.forEach(tooltipTriggerEl => {
            new bootstrap.Tooltip(tooltipTriggerEl, {
                trigger: 'hover focus'
            });
        });
    }
    
    // Inicializar popovers se existirem
    if (popoverTriggerList.length > 0 && typeof bootstrap.Popover !== 'undefined') {
        popoverTriggerList.forEach(popoverTriggerEl => {
            new bootstrap.Popover(popoverTriggerEl);
        });
    }
    
    // Tratamento global de erros
    window.addEventListener('error', function(event) {
        console.error('Erro global:', event.error);
    });
    
    // Verificar se o Bootstrap está carregado
    if (typeof bootstrap === 'undefined') {
        console.warn('Bootstrap não está carregado!');
    }
    
    // Verificar sessão periodicamente
    function checkSession() {
        fetch("/api/core_status", { 
            method: 'GET',
            credentials: 'include'
        })
        .then(response => {
            if (response.status === 401) {
                console.warn('Sessão expirada. Redirecionando para login...');
                window.location.href = "/login";
            }
            return response.json();
        })
        .catch(error => console.error('Erro ao verificar sessão:', error));
    }
    
    // Verificar sessão a cada 5 minutos
    const sessionCheckInterval = setInterval(checkSession, 300000);
    
    // Verificar imediatamente
    checkSession();
    
    // Limpar ao sair
    window.addEventListener('beforeunload', () => {
        clearInterval(sessionCheckInterval);
    });
});
