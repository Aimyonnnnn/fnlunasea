import { initializeApp } from "firebase/app";
import { getFirestore } from "firebase/firestore";
import { getAuth, signInAnonymously } from "firebase/auth";
import { getStorage } from "firebase/storage";

const firebaseConfig = {
  apiKey: "AIzaSyD8MylQsWFiFIUbbfHYuaBelsePExtJ0ZQ",
  authDomain: "useradmin-16a32.firebaseapp.com",
  projectId: "useradmin-16a32",
  storageBucket: "useradmin-16a32.firebasestorage.app",
  messagingSenderId: "508007467701",
  appId: "1:508007467701:web:76ec74b35e4ef556beccfc",
  measurementId: "G-XW61LTSZS8"
};

const app = initializeApp(firebaseConfig);
const db = getFirestore(app);
const auth = getAuth(app);
const storage = getStorage(app);
console.log("🔥 연결된 Firebase 프로젝트:", firebaseConfig.projectId); 

signInAnonymously(auth)
  .then(() => {
    console.log("익명 로그인 성공");
  })
  .catch((error) => {
    console.error("익명 로그인 실패:", error);
  });

export { db, auth, storage }; 


