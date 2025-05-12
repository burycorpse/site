document.addEventListener('DOMContentLoaded', () => {
    console.log("Homepage DOM Loaded");

    // Set current year in footer
    const yearSpan = document.getElementById('year');
    if (yearSpan) {
        yearSpan.textContent = new Date().getFullYear();
    }

    // --- Header Scroll Effect ---
    const header = document.querySelector('.main-header');
    let lastScrollTop = 0; // To detect scroll direction (optional for more effects)
    const scrollThreshold = 50; // Pixels to scroll before effect triggers

    if (header) {
        window.addEventListener('scroll', () => {
            let scrollTop = window.pageYOffset || document.documentElement.scrollTop;

            if (scrollTop > scrollThreshold) {
                header.classList.add('scrolled');
            } else {
                header.classList.remove('scrolled');
            }
            // Optional: Add effects based on scroll direction
            // if (scrollTop > lastScrollTop && scrollTop > header.offsetHeight){
            //     // Downscroll, hide header (example)
            //     header.style.top = `-${header.offsetHeight}px`;
            // } else {
            //     // Upscroll, show header
            //     header.style.top = "0";
            // }
            lastScrollTop = scrollTop <= 0 ? 0 : scrollTop; // For Mobile or negative scrolling
        }, false);
        console.log("Header scroll effect initialized.");
    } else {
        console.warn("Main header element not found for scroll effect.");
    }


    // --- 3D Panel Mouse Interaction ---
    const panel3D = document.getElementById('panel-3d');
    const perspectiveContainer = document.querySelector('.panel-perspective-container');

    if (panel3D && perspectiveContainer) {
        const handleMouseMove = (e) => {
            const rect = perspectiveContainer.getBoundingClientRect();
            const x = e.clientX - rect.left - rect.width / 2;
            const y = e.clientY - rect.top - rect.height / 2;
            const maxRotateX = 8;
            const maxRotateY = 12;
            const rotateY = (x / (rect.width / 2)) * -maxRotateY;
            const rotateX = (y / (rect.height / 2)) * maxRotateX;

            requestAnimationFrame(() => {
                 panel3D.style.transform = `rotateX(${rotateX}deg) rotateY(${rotateY}deg)`;
                 panel3D.style.transition = 'transform 0.05s linear';
            });
        };

        const handleMouseLeave = () => {
             requestAnimationFrame(() => {
                panel3D.style.transform = '';
                panel3D.style.transition = 'transform 0.5s ease-out';
            });
        };

        perspectiveContainer.addEventListener('mousemove', handleMouseMove);
        perspectiveContainer.addEventListener('mouseleave', handleMouseLeave);
        console.log("3D panel cursor tracking initialized.");
    } else {
        console.warn("3D panel element or container not found for mouse interaction.");
    }

    // --- Scroll Animations for Feature Cards ---
     const featureCards = document.querySelectorAll('.feature-card');
     if (featureCards.length > 0 && 'IntersectionObserver' in window) {
        const observerOptions = { root: null, rootMargin: '0px', threshold: 0.1 };
        const observerCallback = (entries, observer) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    setTimeout(() => {
                        entry.target.classList.add('visible');
                    }, parseInt(entry.target.dataset.delay || '0', 10));
                    observer.unobserve(entry.target);
                }
            });
        };
        const featureObserver = new IntersectionObserver(observerCallback, observerOptions);
        featureCards.forEach((card, index) => {
            // card.dataset.delay = index * 100; // Example: Stagger delay
            featureObserver.observe(card);
        });
        console.log("Intersection Observer set up for feature cards.");
    } else {
         featureCards.forEach(card => card.classList.add('visible'));
         if (!('IntersectionObserver' in window)) {
             console.warn("Intersection Observer not supported, animations might not work as intended.");
         }
    }

}); // End DOMContentLoaded
