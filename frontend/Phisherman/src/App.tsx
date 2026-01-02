import { useState, useEffect } from "react";
import { Navbar } from "./components/Navbar";
import { Hero } from "./components/Hero";
import { Features } from "./components/Features";
import { Download } from "./components/Download";
import { Footer } from "./components/Footer";
import { LoadingScreen } from "./components/LoadingScreen";
import "./App.css";

function App() {
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const timer = setTimeout(() => {
      setLoading(false);
    }, 1500); // Minimum duration for the loading animation

    return () => clearTimeout(timer);
  }, []);

  return (
    <>
      {loading && <LoadingScreen />}
      <div className={`app ${loading ? 'loading' : 'loaded'}`}>
        <Navbar />
        <main>
          <Hero />
          <Features />
          <Download />
        </main>
        <Footer />
      </div>
    </>
  );
}

export default App;
