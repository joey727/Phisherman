import React from 'react';
import './LoadingScreen.css';

export const LoadingScreen: React.FC = () => {
    return (
        <div className="loading-screen">
            <div className="loading-content">
                <div className="logo-container">
                    <span className="logo-text glow-text">PHISHERMAN</span>
                </div>
                <div className="progress-bar-container">
                    <div className="progress-bar"></div>
                </div>
                <p className="loading-subtitle">staying secured...</p>
            </div>
        </div>
    );
};
