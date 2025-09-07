document.addEventListener('DOMContentLoaded', function() {
    // universal confirm for forms that include hidden input[name="action"] or button[name="action"]
    document.querySelectorAll('form').forEach(form => {
        form.addEventListener('submit', function(e) {
            // find declared action (hidden input or submit button)
            const hidden = form.querySelector('input[name="action"]');
            const buttonAction = e.submitter ? (e.submitter.getAttribute('name') === 'action' ? e.submitter.value : null) : null;
            const action = (hidden && hidden.value) ? hidden.value : buttonAction;

            let confirmMsg = null;
            if (action === 'delete') confirmMsg = 'Delete this key? This is permanent!';
            else if (action === 'ban') confirmMsg = 'Ban this key/HWID?';
            else if (action === 'freeze') confirmMsg = 'Toggle freeze for this key?';
            if (confirmMsg && !confirm(confirmMsg)) {
                e.preventDefault();
            }
        });
    });

    // fade-in
    const main = document.querySelector('.main-content');
    if (main) {
        main.style.opacity = 0;
        setTimeout(()=> {
            main.style.transition = 'opacity 0.45s ease';
            main.style.opacity = 1;
        }, 80);
    }

    // Actions scroll blur effects
    function updateScrollBlur() {
        const scrollContainers = document.querySelectorAll('.actions-scroll');
        
        scrollContainers.forEach(container => {
            const scrollTop = container.scrollTop;
            const scrollHeight = container.scrollHeight;
            const clientHeight = container.clientHeight;
            const scrollBottom = scrollHeight - clientHeight - scrollTop;

            // Remove existing classes
            container.classList.remove('scroll-top', 'scroll-bottom');

            // Add classes based on scroll position
            if (scrollTop > 10) {
                container.classList.add('scroll-top');
            }
            if (scrollBottom > 10) {
                container.classList.add('scroll-bottom');
            }
        });
    }

    // Initialize scroll blur effects
    const actionsScrolls = document.querySelectorAll('.actions-scroll');
    actionsScrolls.forEach(scroll => {
        scroll.addEventListener('scroll', updateScrollBlur);
        // Check initial state
        setTimeout(updateScrollBlur, 100);
    });

    // Initial blur check
    updateScrollBlur();

    // Handle window resize
    window.addEventListener('resize', updateScrollBlur);
});