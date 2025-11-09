const prevBtn = document.getElementById('prevBtn')
const nextBtn = document.getElementById('nextBtn')
const imgElem = document.getElementById('marsImage')

let imgs = []

let idx = 0

function nav(delta) {
  idx = (idx + delta + imgs.length) % imgs.length
  imgElem.src = `/api/view?path=${imgs[idx]}`
}

// Initialize the application when the page loads
window.addEventListener('load', async () => {
  const starsContainer = document.getElementById('stars')
  const numStars = 100
  
  for (let i = 0; i < 100; i++) {
    const star = document.createElement('div')
    star.className = 'star'
    star.style.left = Math.random() * 100 + '%'
    star.style.top = Math.random() * 100 + '%'
    star.style.width = Math.random() * 3 + 1 + 'px'
    star.style.height = star.style.width
    star.style.animationDelay = Math.random() * 2 + 's'
    starsContainer.appendChild(star)
  }

  prevBtn.addEventListener('click', () => nav(-1))
  nextBtn.addEventListener('click', () => nav(1))

  imgs = await (await fetch('/api/list?path=imgs')).json()

  nav(0)
})
