// Reference to the HTML elements
const loginDiv = document.getElementById("login-div");
const logoutDiv = document.getElementById("logout-div");

// Login function
function login() {
  const email = document.getElementById("email").value;
  const password = document.getElementById("password").value;
  firebase.auth().signInWithEmailAndPassword(email, password)
    .then((userCredential) => {
      // Signed in
      var user = userCredential.user;
      loginDiv.style.display = "none";
      logoutDiv.style.display = "block";
    })
    .catch((error) => {
      var errorCode = error.code;
      var errorMessage = error.message;
      alert("Error: " + errorMessage);
    });
}

// Sign up function
function signup() {
  const email = document.getElementById("email").value;
  const password = document.getElementById("password").value;
  firebase.auth().createUserWithEmailAndPassword(email, password)
    .then((userCredential) => {
      // Signed up
      var user = userCredential.user;
      loginDiv.style.display = "none";
      logoutDiv.style.display = "block";
    })
    .catch((error) => {
      var errorCode = error.code;
      var errorMessage = error.message;
      alert("Error: " + errorMessage);
    });
}

// Logout function
function logout() {
  firebase.auth().signOut().then(() => {
    loginDiv.style.display = "block";
    logoutDiv.style.display = "none";
  }).catch((error) => {
    alert("Error: " + error.message);
  });
}

// Monitor auth state
firebase.auth().onAuthStateChanged((user) => {
  if (user) {
    // User is signed in
    loginDiv.style.display = "none";
    logoutDiv.style.display = "block";
  } else {
    // User is signed out
    loginDiv.style.display = "block";
    logoutDiv.style.display = "none";
  }
});
