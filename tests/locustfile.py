from locust import HttpUser, task, between
import json
import random

class HealthcareUser(HttpUser):
    wait_time = between(1, 3)
    
    def on_start(self):
        """Login at the start of each user session"""
        self.login()
    
    def login(self):
        """Login with different user roles"""
        users = [
            {"username": "admin@healthcare.com", "password": "admin123"},
            {"username": "doctor@healthcare.com", "password": "doctor123"},
            {"username": "nurse@healthcare.com", "password": "nurse123"},
            {"username": "clerk@healthcare.com", "password": "clerk123"},
            {"username": "patient@healthcare.com", "password": "patient123"}
        ]
        
        user = random.choice(users)
        response = self.client.post("/api/auth/login", json=user)
        
        if response.status_code == 200:
            data = response.json()
            self.token = data.get('access_token')
            self.headers = {"Authorization": f"Bearer {self.token}"}
        else:
            self.token = None
            self.headers = {}
    
    @task(3)
    def health_check(self):
        """Health check endpoint - high frequency"""
        self.client.get("/api/health/health")
    
    @task(2)
    def get_patients(self):
        """Get patients list - requires authentication"""
        if self.token:
            self.client.get("/api/patients/", headers=self.headers)
    
    @task(1)
    def search_patients(self):
        """Search patients - requires authentication"""
        if self.token:
            search_terms = ["john", "smith", "doe", "jane", "brown"]
            search_term = random.choice(search_terms)
            self.client.get(f"/api/patients/search?q={search_term}", headers=self.headers)
    
    @task(1)
    def get_records(self):
        """Get medical records - requires authentication"""
        if self.token:
            self.client.get("/api/records/", headers=self.headers)
    
    @task(1)
    def get_record_types(self):
        """Get record types - requires authentication"""
        if self.token:
            self.client.get("/api/records/types", headers=self.headers)
    
    @task(1)
    def get_user_profile(self):
        """Get user profile - requires authentication"""
        if self.token:
            self.client.get("/api/auth/profile", headers=self.headers)
    
    @task(1)
    def get_roles(self):
        """Get available roles - requires authentication"""
        if self.token:
            self.client.get("/api/users/roles", headers=self.headers)

class AdminUser(HealthcareUser):
    """Admin user with additional privileges"""
    weight = 1  # Lower weight for admin users
    
    @task(1)
    def get_users(self):
        """Get users list - admin only"""
        if self.token:
            self.client.get("/api/users/", headers=self.headers)
    
    @task(1)
    def get_audit_logs(self):
        """Get audit logs - admin only"""
        if self.token:
            self.client.get("/api/audit/logs", headers=self.headers)
    
    @task(1)
    def get_suspicious_activity(self):
        """Get suspicious activity - admin only"""
        if self.token:
            self.client.get("/api/audit/suspicious", headers=self.headers)
    
    @task(1)
    def get_audit_summary(self):
        """Get audit summary - admin only"""
        if self.token:
            self.client.get("/api/audit/summary", headers=self.headers)

class DoctorUser(HealthcareUser):
    """Doctor user with patient management tasks"""
    weight = 2  # Medium weight for doctors
    
    @task(2)
    def create_patient(self):
        """Create patient - doctor privilege"""
        if self.token:
            patient_data = {
                "first_name": f"Test{random.randint(1000, 9999)}",
                "last_name": f"Patient{random.randint(1000, 9999)}",
                "date_of_birth": "1980-01-01",
                "gender": random.choice(["Male", "Female"]),
                "phone": f"+1-555-{random.randint(1000, 9999)}",
                "email": f"test{random.randint(1000, 9999)}@example.com",
                "blood_type": random.choice(["A+", "A-", "B+", "B-", "O+", "O-", "AB+", "AB-"])
            }
            self.client.post("/api/patients/", json=patient_data, headers=self.headers)
    
    @task(2)
    def create_record(self):
        """Create medical record - doctor privilege"""
        if self.token:
            record_data = {
                "patient_id": random.randint(1, 100),  # Assuming patients exist
                "record_type": random.choice(["consultation", "lab_result", "prescription"]),
                "title": f"Medical Record {random.randint(1000, 9999)}",
                "content": f"Patient consultation notes for record {random.randint(1000, 9999)}",
                "priority": random.choice(["low", "normal", "high"])
            }
            self.client.post("/api/records/", json=record_data, headers=self.headers)

class NurseUser(HealthcareUser):
    """Nurse user with patient care tasks"""
    weight = 3  # Higher weight for nurses
    
    @task(3)
    def update_patient(self):
        """Update patient information - nurse privilege"""
        if self.token:
            patient_id = random.randint(1, 100)  # Assuming patients exist
            update_data = {
                "allergies": random.choice(["None", "Penicillin", "Shellfish", "Peanuts"]),
                "emergency_contact": f"Emergency Contact {random.randint(1000, 9999)}"
            }
            self.client.put(f"/api/patients/{patient_id}", json=update_data, headers=self.headers)
    
    @task(2)
    def get_patient_records(self):
        """Get patient records - nurse privilege"""
        if self.token:
            patient_id = random.randint(1, 100)  # Assuming patients exist
            self.client.get(f"/api/patients/{patient_id}/records", headers=self.headers)

class PatientUser(HealthcareUser):
    """Patient user with limited access"""
    weight = 5  # Highest weight for patients (most common)
    
    @task(5)
    def view_own_profile(self):
        """View own profile - patient privilege"""
        if self.token:
            self.client.get("/api/auth/profile", headers=self.headers)
    
    @task(3)
    def update_profile(self):
        """Update own profile - patient privilege"""
        if self.token:
            update_data = {
                "first_name": f"Updated{random.randint(1000, 9999)}",
                "last_name": f"Name{random.randint(1000, 9999)}"
            }
            self.client.put("/api/auth/profile", json=update_data, headers=self.headers)

class ClerkUser(HealthcareUser):
    """Clerk user with administrative tasks"""
    weight = 2  # Medium weight for clerks
    
    @task(3)
    def search_patients_advanced(self):
        """Advanced patient search - clerk privilege"""
        if self.token:
            search_params = {
                "q": random.choice(["john", "smith", "doe", "jane", "brown"]),
                "gender": random.choice(["Male", "Female"]),
                "blood_type": random.choice(["A+", "O+", "B+", "AB+"])
            }
            query_string = "&".join([f"{k}={v}" for k, v in search_params.items()])
            self.client.get(f"/api/patients/search?{query_string}", headers=self.headers)
    
    @task(2)
    def bulk_operations(self):
        """Simulate bulk operations - clerk privilege"""
        if self.token:
            # Simulate bulk patient export
            self.client.get("/api/patients/?per_page=50", headers=self.headers)

# Additional load test scenarios
class HighLoadUser(HealthcareUser):
    """High load user for stress testing"""
    weight = 1  # Low weight for stress testing
    
    @task(10)
    def rapid_requests(self):
        """Make rapid requests to test system performance"""
        endpoints = [
            "/api/health/health",
            "/api/health/info",
            "/api/auth/profile"
        ]
        endpoint = random.choice(endpoints)
        if "profile" in endpoint and self.token:
            self.client.get(endpoint, headers=self.headers)
        else:
            self.client.get(endpoint)
    
    @task(5)
    def concurrent_operations(self):
        """Simulate concurrent operations"""
        if self.token:
            # Simulate multiple concurrent requests
            self.client.get("/api/patients/", headers=self.headers)
            self.client.get("/api/records/", headers=self.headers)
            self.client.get("/api/health/health")

# Performance monitoring tasks
class MonitoringUser(HealthcareUser):
    """User for monitoring system performance"""
    weight = 1  # Low weight for monitoring
    
    @task(1)
    def detailed_health_check(self):
        """Detailed health check for monitoring"""
        self.client.get("/api/health/detailed")
    
    @task(1)
    def metrics_endpoint(self):
        """Check metrics endpoint"""
        self.client.get("/api/health/metrics")
    
    @task(1)
    def system_info(self):
        """Get system information"""
        self.client.get("/api/health/info")
