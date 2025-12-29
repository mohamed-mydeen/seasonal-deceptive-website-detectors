"""
Seasonal Fake Offer & Phishing Website Detection System
Streamlit Frontend Interface with MySQL Database Integration
"""

import streamlit as st
from risk_engine import calculate_risk
import time
import mysql.connector
from mysql.connector import Error
from datetime import datetime
import pandas as pd
from decimal import Decimal

# ==================== DATABASE CONFIGURATION ====================
DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': 'Mohamedmydeen@4262',  # Change this
    'database': 'scam_detector_db',
    'port': 3306
}

# ==================== HELPER FUNCTION - MUST BE FIRST ====================
def convert_decimal(obj):
    """Convert Decimal types to int/float for Streamlit compatibility"""
    if isinstance(obj, dict):
        return {key: convert_decimal(val) for key, val in obj.items()}
    elif isinstance(obj, list):
        return [convert_decimal(item) for item in obj]
    elif isinstance(obj, Decimal):
        return int(obj) if obj % 1 == 0 else float(obj)
    return obj

# ==================== DATABASE FUNCTIONS ====================
def create_connection():
    """Create database connection"""
    try:
        connection = mysql.connector.connect(**DB_CONFIG)
        return connection
    except Error as e:
        st.error(f"Database Connection Error: {e}")
        return None

def initialize_database():
    """Create database and tables if they don't exist"""
    try:
        connection = mysql.connector.connect(
            host=DB_CONFIG['host'],
            user=DB_CONFIG['user'],
            password=DB_CONFIG['password'],
            port=DB_CONFIG['port']
        )
        cursor = connection.cursor()
        
        # Create database
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {DB_CONFIG['database']}")
        cursor.execute(f"USE {DB_CONFIG['database']}")
        
        # Create analysis table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS website_analysis (
                id INT AUTO_INCREMENT PRIMARY KEY,
                url VARCHAR(500) NOT NULL,
                total_risk_score INT NOT NULL,
                risk_category VARCHAR(50) NOT NULL,
                confidence VARCHAR(50) NOT NULL,
                url_analysis_score INT,
                domain_analysis_score INT,
                ssl_analysis_score INT,
                content_analysis_score INT,
                all_issues LONGTEXT,
                recommendations LONGTEXT,
                analysis_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                user_feedback VARCHAR(20),
                INDEX idx_url (url),
                INDEX idx_date (analysis_date),
                INDEX idx_risk_score (total_risk_score)
            )
        """)
        
        # Create user feedback table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_feedback (
                id INT AUTO_INCREMENT PRIMARY KEY,
                analysis_id INT NOT NULL,
                feedback VARCHAR(100) NOT NULL,
                comment TEXT,
                feedback_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (analysis_id) REFERENCES website_analysis(id),
                INDEX idx_analysis_id (analysis_id)
            )
        """)
        
        # Create statistics table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS daily_statistics (
                id INT AUTO_INCREMENT PRIMARY KEY,
                date DATE NOT NULL UNIQUE,
                total_scans INT DEFAULT 0,
                safe_websites INT DEFAULT 0,
                suspicious_websites INT DEFAULT 0,
                deceptive_websites INT DEFAULT 0,
                avg_risk_score FLOAT,
                INDEX idx_date (date)
            )
        """)
        
        connection.commit()
        cursor.close()
        connection.close()
        return True
    except Error as e:
        st.error(f"Database initialization error: {e}")
        return False

def save_analysis_to_db(url, results):
    """Save analysis results to database"""
    try:
        connection = create_connection()
        if not connection:
            return None
        
        cursor = connection.cursor()
        
        # Convert lists to JSON strings for storage
        issues_str = " | ".join(results['all_issues']) if results['all_issues'] else ""
        recommendations_str = " | ".join(results['recommendations']) if results['recommendations'] else ""
        
        insert_query = """
            INSERT INTO website_analysis 
            (url, total_risk_score, risk_category, confidence, 
             url_analysis_score, domain_analysis_score, ssl_analysis_score, 
             content_analysis_score, all_issues, recommendations)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        
        values = (
            url,
            results['total_risk_score'],
            results['risk_category'],
            results['confidence'],
            results['module_scores'].get('url_analysis', 0),
            results['module_scores'].get('domain_analysis', 0),
            results['module_scores'].get('ssl_analysis', 0),
            results['module_scores'].get('content_analysis', 0),
            issues_str,
            recommendations_str
        )
        
        cursor.execute(insert_query, values)
        connection.commit()
        
        analysis_id = cursor.lastrowid
        cursor.close()
        connection.close()
        
        return analysis_id
    except Error as e:
        st.error(f"Error saving to database: {e}")
        return None

def save_user_feedback(analysis_id, feedback, comment=""):
    """Save user feedback to database"""
    try:
        connection = create_connection()
        if not connection:
            return False
        
        cursor = connection.cursor()
        
        insert_query = """
            INSERT INTO user_feedback (analysis_id, feedback, comment)
            VALUES (%s, %s, %s)
        """
        
        cursor.execute(insert_query, (analysis_id, feedback, comment))
        connection.commit()
        cursor.close()
        connection.close()
        
        return True
    except Error as e:
        st.error(f"Error saving feedback: {e}")
        return False

def get_analysis_history(limit=10):
    """Retrieve analysis history from database"""
    try:
        connection = create_connection()
        if not connection:
            return None
        
        cursor = connection.cursor(dictionary=True)
        cursor.execute("""
            SELECT id, url, total_risk_score, risk_category, confidence, analysis_date, user_feedback
            FROM website_analysis
            ORDER BY analysis_date DESC
            LIMIT %s
        """, (limit,))
        
        results = cursor.fetchall()
        cursor.close()
        connection.close()
        
        return results
    except Error as e:
        st.error(f"Error retrieving history: {e}")
        return None

def get_statistics():
    """Get analysis statistics"""
    try:
        connection = create_connection()
        if not connection:
            return None
        
        cursor = connection.cursor(dictionary=True)
        cursor.execute("""
            SELECT 
                COUNT(*) as total_scans,
                SUM(CASE WHEN total_risk_score < 25 THEN 1 ELSE 0 END) as safe_count,
                SUM(CASE WHEN total_risk_score BETWEEN 25 AND 44 THEN 1 ELSE 0 END) as caution_count,
                SUM(CASE WHEN total_risk_score BETWEEN 45 AND 69 THEN 1 ELSE 0 END) as suspicious_count,
                SUM(CASE WHEN total_risk_score >= 70 THEN 1 ELSE 0 END) as deceptive_count,
                AVG(total_risk_score) as avg_risk_score
            FROM website_analysis
        """)
        
        stats = cursor.fetchone()
        cursor.close()
        connection.close()
        
        # Convert Decimal values to int/float
        if stats:
            return convert_decimal(stats)
        return None
    except Error as e:
        st.error(f"Error retrieving statistics: {e}")
        return None

def update_daily_statistics():
    """Update daily statistics"""
    try:
        connection = create_connection()
        if not connection:
            return False
        
        cursor = connection.cursor()
        today = datetime.now().date()
        
        cursor.execute("""
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN total_risk_score < 25 THEN 1 ELSE 0 END) as safe,
                SUM(CASE WHEN total_risk_score BETWEEN 25 AND 44 THEN 1 ELSE 0 END) as caution,
                SUM(CASE WHEN total_risk_score BETWEEN 45 AND 69 THEN 1 ELSE 0 END) as suspicious,
                SUM(CASE WHEN total_risk_score >= 70 THEN 1 ELSE 0 END) as deceptive,
                AVG(total_risk_score) as avg_score
            FROM website_analysis
            WHERE DATE(analysis_date) = %s
        """, (today,))
        
        stats = cursor.fetchone()
        
        if stats and stats[0] > 0:
            cursor.execute("""
                INSERT INTO daily_statistics (date, total_scans, safe_websites, suspicious_websites, deceptive_websites, avg_risk_score)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                total_scans = VALUES(total_scans),
                safe_websites = VALUES(safe_websites),
                suspicious_websites = VALUES(suspicious_websites),
                deceptive_websites = VALUES(deceptive_websites),
                avg_risk_score = VALUES(avg_risk_score)
            """, (today, stats[0], stats[1], stats[3], stats[4], stats[5]))
            
            connection.commit()
        
        cursor.close()
        connection.close()
        return True
    except Error as e:
        st.error(f"Error updating statistics: {e}")
        return False

# ==================== PAGE CONFIGURATION ====================
st.set_page_config(
    page_title="Seasonal Scam Detector",
    page_icon="🛡️",
    layout="wide"
)

# ==================== CUSTOM CSS ====================
st.markdown("""
    <style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        text-align: center;
        color: #1E88E5;
        margin-bottom: 1rem;
    }
    .sub-header {
        text-align: center;
        color: #666;
        margin-bottom: 2rem;
    }
    .safe-box {
        padding: 20px;
        border-radius: 10px;
        background-color: #d4edda;
        border-left: 5px solid #28a745;
        margin: 10px 0;
    }
    .caution-box {
        padding: 20px;
        border-radius: 10px;
        background-color: #fff3cd;
        border-left: 5px solid #ffc107;
        margin: 10px 0;
    }
    .suspicious-box {
        padding: 20px;
        border-radius: 10px;
        background-color: #ffe0b2;
        border-left: 5px solid #ff9800;
        margin: 10px 0;
    }
    .danger-box {
        padding: 20px;
        border-radius: 10px;
        background-color: #f8d7da;
        border-left: 5px solid #dc3545;
        margin: 10px 0;
    }
    .metric-card {
        padding: 15px;
        border-radius: 8px;
        background-color: #f8f9fa;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    </style>
""", unsafe_allow_html=True)

# Initialize database on app load
if 'db_initialized' not in st.session_state:
    initialize_database()
    st.session_state.db_initialized = True

# ==================== HEADER ====================
st.markdown('<div class="main-header">🛡️ Seasonal Fake Offer & Phishing Detector</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-header">Protect yourself from seasonal scams targeting Indian users</div>', unsafe_allow_html=True)

# ==================== NAVIGATION TABS ====================
tab1, tab2, tab3, tab4 = st.tabs(["🔍 Analyze", "📊 Dashboard", "📜 History", "ℹ️ About"])

# ==================== TAB 1: ANALYSIS ====================
with tab1:
    with st.expander("ℹ️ About This Tool"):
        st.markdown("""
        This cybersecurity tool analyzes websites for deceptive patterns commonly used in seasonal scams.
        
        **Detection Features:**
        - 🔍 URL pattern analysis
        - 📅 Domain age verification
        - 🔒 SSL certificate validation
        - 📝 Scam keyword detection
        - 🧠 Psychological manipulation detection
        """)
    
    st.markdown("---")
    col1, col2 = st.columns([3, 1])
    
    with col1:
        url_input = st.text_input(
            "🔗 Enter Website URL to Analyze",
            placeholder="https://example.com",
            help="Enter the complete URL including http:// or https://"
        )
    
    with col2:
        st.markdown("<br>", unsafe_allow_html=True)
        analyze_button = st.button("🔍 Analyze Website", type="primary", use_container_width=True)
    
    if analyze_button and url_input:
        if not url_input.startswith(('http://', 'https://')):
            st.error("⚠️ Please enter a valid URL starting with http:// or https://")
        else:
            progress_bar = st.progress(0)
            progress_text = st.empty()
            
            progress_text.text("🔍 Analyzing URL patterns...")
            progress_bar.progress(25)
            time.sleep(0.3)
            
            progress_text.text("📅 Checking domain age...")
            progress_bar.progress(50)
            time.sleep(0.3)
            
            progress_text.text("🔒 Validating SSL certificate...")
            progress_bar.progress(75)
            time.sleep(0.3)
            
            progress_text.text("📝 Analyzing webpage content...")
            progress_bar.progress(90)
            
            try:
                results = calculate_risk(url_input)
                
                # Save to database
                analysis_id = save_analysis_to_db(url_input, results)
                update_daily_statistics()
                
                progress_bar.progress(100)
                progress_text.text("✅ Analysis Complete!")
                time.sleep(0.5)
                
                progress_text.empty()
                progress_bar.empty()
                
                # Display results
                st.markdown("---")
                st.markdown("## 📊 Analysis Results")
                
                risk_score = results['total_risk_score']
                risk_category = results['risk_category']
                
                if risk_score >= 70:
                    box_class = "danger-box"
                elif risk_score >= 45:
                    box_class = "suspicious-box"
                elif risk_score >= 25:
                    box_class = "caution-box"
                else:
                    box_class = "safe-box"
                
                st.markdown(f"""
                    <div class="{box_class}">
                        <h2 style="margin: 0;">{risk_category}</h2>
                        <h1 style="margin: 10px 0;">Risk Score: {risk_score}/100</h1>
                        <p style="margin: 0;"><strong>Confidence:</strong> {results['confidence']}</p>
                    </div>
                """, unsafe_allow_html=True)
                
                # Module scores
                st.markdown("### 📈 Detailed Risk Breakdown")
                
                score_cols = st.columns(4)
                modules = [
                    ("URL Analysis", results['module_scores'].get('url_analysis', 0), 30),
                    ("Domain Check", results['module_scores'].get('domain_analysis', 0), 25),
                    ("SSL Security", results['module_scores'].get('ssl_analysis', 0), 20),
                    ("Content Scan", results['module_scores'].get('content_analysis', 0), 25)
                ]
                
                for col, (module_name, score, max_score) in zip(score_cols, modules):
                    with col:
                        percentage = (score / max_score) * 100 if max_score > 0 else 0
                        st.metric(label=module_name, value=f"{score}/{max_score}", delta=f"{percentage:.0f}%")
                
                # Issues detected
                if results['all_issues']:
                    st.markdown("### ⚠️ Issues Detected")
                    for i, issue in enumerate(results['all_issues'], 1):
                        st.markdown(f"{i}. {issue}")
                
                # Recommendations
                st.markdown("### 💡 Recommendations")
                for recommendation in results['recommendations']:
                    st.markdown(f"- {recommendation}")
                
                # User feedback section
                st.markdown("### 📝 Report Accuracy")
                feedback_col1, feedback_col2 = st.columns([2, 1])
                
                with feedback_col1:
                    feedback = st.radio(
                        "Was this analysis helpful?",
                        ["Not Selected", "Accurate", "Inaccurate", "Uncertain"],
                        horizontal=True,
                        key=f"feedback_{analysis_id}"
                    )
                
                with feedback_col2:
                    if feedback != "Not Selected":
                        if st.button("Submit Feedback", key=f"btn_{analysis_id}"):
                            if save_user_feedback(analysis_id, feedback):
                                st.success("✅ Feedback saved successfully!")
                
                # Warning banner
                if risk_score >= 70:
                    st.error("🚨 CRITICAL WARNING: This website exhibits characteristics of a deceptive/phishing site. DO NOT share personal information.")
                
            except Exception as e:
                st.error(f"❌ Error during analysis: {str(e)}")

# ==================== TAB 2: DASHBOARD ====================
with tab2:
    st.markdown("### 📊 System Dashboard")
    
    stats = get_statistics()
    
    if stats:
        col1, col2, col3, col4, col5 = st.columns(5)
        
        with col1:
            st.metric("Total Scans", int(stats['total_scans'] or 0))
        with col2:
            st.metric("Safe Sites", int(stats['safe_count'] or 0), "✅")
        with col3:
            st.metric("Caution Sites", int(stats['caution_count'] or 0), "⚡")
        with col4:
            st.metric("Suspicious Sites", int(stats['suspicious_count'] or 0), "⚠️")
        with col5:
            st.metric("Deceptive Sites", int(stats['deceptive_count'] or 0), "🚨")
        
        st.markdown("---")
        
        # Average risk score
        avg_score = float(stats['avg_risk_score'] or 0)
        col1, col2 = st.columns([2, 1])
        with col1:
            st.markdown(f"**Average Risk Score:** {avg_score:.1f}/100")
        
        # Distribution chart
        if stats['total_scans'] and int(stats['total_scans']) > 0:
            distribution = {
                'Safe': int(stats['safe_count'] or 0),
                'Caution': int(stats['caution_count'] or 0),
                'Suspicious': int(stats['suspicious_count'] or 0),
                'Deceptive': int(stats['deceptive_count'] or 0)
            }
            
            st.bar_chart(distribution)
    else:
        st.info("No data available yet. Start scanning websites to see statistics.")

# ==================== TAB 3: HISTORY ====================
with tab3:
    st.markdown("### 📜 Analysis History")
    
    history = get_analysis_history(limit=50)
    
    if history:
        df = pd.DataFrame(history)
        df['analysis_date'] = pd.to_datetime(df['analysis_date']).dt.strftime('%Y-%m-%d %H:%M:%S')
        
        st.dataframe(
            df[['url', 'total_risk_score', 'risk_category', 'confidence', 'analysis_date', 'user_feedback']],
            use_container_width=True,
            hide_index=True
        )
        
        # Export option
        csv = df.to_csv(index=False)
        st.download_button(
            label="📥 Download CSV",
            data=csv,
            file_name=f"analysis_history_{datetime.now().strftime('%Y%m%d')}.csv",
            mime="text/csv"
        )
    else:
        st.info("No analysis history found.")

# ==================== TAB 4: ABOUT ====================
with tab4:
    st.markdown("### About This Application")
    
    st.markdown("""
    **Seasonal Scam Detector** is a comprehensive cybersecurity tool designed to identify and analyze deceptive websites.
    
    **Key Features:**
    - Real-time website analysis
    - Multi-module threat detection
    - MySQL database integration
    - Historical analysis tracking
    - User feedback system
    - Statistical dashboard
    
    **Database Information:**
    - All analyses are stored in MySQL for record-keeping
    - User feedback helps improve detection accuracy
    - Historical data enables trend analysis
    
    **Contact & Support:**
    - Developer: Mohamed Mydeen
    - Report Issues: [Contact Information]
    """)

# ==================== FOOTER ====================
st.markdown("---")
st.markdown("""
    <div style="text-align: center; color: #666; padding: 20px;">
        <p><strong>🛡️ Seasonal Scam Detector v2.0</strong></p>
        <p>With MySQL Database Integration</p>
        <p style="font-size: 0.8rem;">Developed by Mohamed Mydeen</p>
    </div>
""", unsafe_allow_html=True)