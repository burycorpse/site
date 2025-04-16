document.addEventListener('DOMContentLoaded', () => {

    // --- Smooth Scrolling for Navigation Links ---
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const targetId = this.getAttribute('href');
            const targetElement = document.querySelector(targetId);
            if (targetElement) {
                targetElement.scrollIntoView({
                    behavior: 'smooth'
                });
            }
        });
    });

    // --- Intersection Observer for Scroll Animations ---
    const revealElements = document.querySelectorAll('.reveal-on-scroll');

    const observerOptions = {
        root: null, // relative to document viewport
        rootMargin: '0px',
        threshold: 0.1 // Trigger when 10% of the element is visible
    };

    const observerCallback = (entries, observer) => {
        entries.forEach((entry, index) => {
            if (entry.isIntersecting) {
                // Add a staggered delay based on the element's index or position
                const delay = (entry.target.dataset.delay || index * 0.1) + 's';
                entry.target.style.transitionDelay = delay;

                entry.target.classList.add('is-visible');
                observer.unobserve(entry.target); // Stop observing once visible
            }
        });
    };

    const observer = new IntersectionObserver(observerCallback, observerOptions);

    revealElements.forEach((el, index) => {
         // Optional: Set a data-delay attribute in HTML for custom delays
         // if (!el.dataset.delay) el.dataset.delay = index * 0.1; // Example default stagger
        observer.observe(el);
    });


    // --- Optional: Hero Product Display Mouse Interaction ---
    const heroSection = document.querySelector('.hero');
    const productDisplay = document.getElementById('product-display');

    if (heroSection && productDisplay) {
        heroSection.addEventListener('mousemove', (e) => {
            const rect = heroSection.getBoundingClientRect();
            // Calculate mouse position relative to the center of the hero section
            const x = e.clientX - rect.left - rect.width / 2;
            const y = e.clientY - rect.top - rect.height / 2;

            // Define max rotation angles (adjust for desired sensitivity)
            const maxRotX = 5; // degrees
            const maxRotY = 8; // degrees

            // Calculate rotation based on mouse position (invert Y for natural feel)
            const rotY = (x / (rect.width / 2)) * maxRotY;
            const rotX = -(y / (rect.height / 2)) * maxRotX;

            // Apply a 3D tilt effect using transform (make sure product-display has transition set in CSS)
             // Add perspective in the parent (.hero) for better 3D effect
            heroSection.style.perspective = '1000px';
            productDisplay.style.transform = `rotateX(${rotX}deg) rotateY(${rotY}deg) scale(1)`; // Keep original scale
        });

        // Reset transform when mouse leaves the hero section
        heroSection.addEventListener('mouseleave', () => {
             productDisplay.style.transform = 'rotateX(0deg) rotateY(0deg) scale(1)'; // Reset to entry scale
        });
    }


    // --- Basic Anti-Stealing Deterrent (Still easily bypassed) ---
    // document.addEventListener('contextmenu', event => event.preventDefault());

    console.log("Enhanced Website Initialized.");
}); // End DOMContentLoaded
