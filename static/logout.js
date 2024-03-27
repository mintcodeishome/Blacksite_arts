// Set the idle timeout in milliseconds (1 minute = 60000 milliseconds)
const idleTimeout = 100000;

// Initialize a timer variable
let timer;

// Function to reset the timer
function resetTimer() {
    clearTimeout(timer);
    timer = setTimeout(logout, idleTimeout);
}

// Function to perform the logout action
function logout() {
    // Redirect to the logout route or perform your logout logic here
    window.location.href = '/logout'; // Change this to your logout URL
}

// Add event listeners to reset the timer on user activity
document.addEventListener('mousemove', resetTimer);
document.addEventListener('keypress', resetTimer);

// Initialize the timer when the page loads
resetTimer();
