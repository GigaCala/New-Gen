const themeToggle = document.querySelector('.theme-toggle');
const themePanel = document.querySelector('#themePanel');
const themeOptions = document.querySelectorAll('.theme-option');
let currentTheme = localStorage.getItem('newgen-theme') || 'dark';

document.body.setAttribute('data-theme', currentTheme);

const syncThemeButtons = () => {
  themeOptions.forEach((button) => {
    const isActive = button.dataset.themeOption === currentTheme;
    button.classList.toggle('active', isActive);
  });
};

syncThemeButtons();

if (themeToggle && themePanel) {
  themeToggle.addEventListener('click', () => {
    themePanel.classList.toggle('open');
  });
}

themeOptions.forEach((button) => {
  button.addEventListener('click', () => {
    currentTheme = button.dataset.themeOption;
    document.body.setAttribute('data-theme', currentTheme);
    localStorage.setItem('newgen-theme', currentTheme);
    syncThemeButtons();
    if (themePanel) {
      themePanel.classList.remove('open');
    }
  });
});

const menuButton = document.querySelector('.menu-toggle');
const navLinks = document.querySelector('.nav-links');

if (menuButton && navLinks) {
  menuButton.addEventListener('click', () => {
    const isOpen = navLinks.style.display === 'flex';
    navLinks.style.display = isOpen ? 'none' : 'flex';
    navLinks.style.position = 'absolute';
    navLinks.style.top = '78px';
    navLinks.style.left = '18px';
    navLinks.style.right = '18px';
    navLinks.style.flexDirection = 'column';
    navLinks.style.padding = '18px';
    navLinks.style.background = 'rgba(12, 18, 32, 0.96)';
    navLinks.style.border = '1px solid rgba(255,255,255,0.08)';
    navLinks.style.borderRadius = '18px';
  });
}

const revealEls = document.querySelectorAll('.reveal');

const observer = new IntersectionObserver((entries) => {
  entries.forEach((entry) => {
    if (entry.isIntersecting) {
      entry.target.style.animationDelay = '0.15s';
      entry.target.classList.add('visible');
      observer.unobserve(entry.target);
    }
  });
}, { threshold: 0.15 });

revealEls.forEach((el) => observer.observe(el));
