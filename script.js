document.addEventListener('DOMContentLoaded', () => {
    console.log("Homepage DOM Loaded");

    // Set current year in footer
    const yearSpan = document.getElementById('year');
    if (yearSpan) {
        yearSpan.textContent = new Date().getFullYear();
    }

    // --- 3D Panel Mouse Interaction ---
    const panel3D = document.getElementById('panel-3d');
    const perspectiveContainer = document.querySelector('.panel-perspective-container'); // Get the container with perspective

    if (panel3D && perspectiveContainer) {
        perspectiveContainer.addEventListener('mousemove', (e) => {
            // Get mouse position relative to the center of the container
            const rect = perspectiveContainer.getBoundingClientRect();
            const x = e.clientX - rect.left - rect.width / 2;
            const y = e.clientY - rect.top - rect.height / 2;

            // Calculate rotation values (adjust multipliers for sensitivity)
            const rotateY = (x / (rect.width / 2)) * -10; // Max rotation +/-10deg
            const rotateX = (y / (rect.height / 2)) * 10;  // Max rotation +/-10deg

            // Apply the transform with clamped values
            panel3D.style.transform = `rotateX(${rotateX}deg) rotateY(${rotateY}deg)`;
        });

        // Reset rotation when mouse leaves the container
        perspectiveContainer.addEventListener('mouseleave', () => {
             // panel3D.style.transform = `rotateX(15deg) rotateY(-10deg)`; // Reset to initial CSS state (or animation state)
             panel3D.style.transform = ''; // Let CSS animation take over again
        });
    } else {
        console.warn("3D panel element not found for mouse interaction.");
    }

    // --- Scroll Animations for Feature Cards ---
    const featureCards = document.querySelectorAll('.feature-card');

    if (featureCards.length > 0 && 'IntersectionObserver' in window) {
        const observerOptions = {
            root: null, // Use the viewport
            rootMargin: '0px',
            threshold: 0.1 // Trigger when 10% of the element is visible
        };

        const observerCallback = (entries, observer) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    entry.target.classList.add('visible');
                    observer.unobserve(entry.target); // Stop observing once visible
                }
            });
        };

        const featureObserver = new IntersectionObserver(observerCallback, observerOptions);
        featureCards.forEach(card => {
            featureObserver.observe(card);
        });
         console.log("Intersection Observer set up for feature cards.");
    } else {
         // Fallback for older browsers or if no cards found: make all visible immediately
         featureCards.forEach(card => card.classList.add('visible'));
         if (!('IntersectionObserver' in window)) {
             console.warn("Intersection Observer not supported, animations might not work as intended.");
         }
    }

});
