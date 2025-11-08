// API service for backend communication
const API_BASE_URL = 'http://localhost:3000/api';

class ApiService {
    constructor() {
        this.token = localStorage.getItem('authToken');
    }

    setToken(token) {
        this.token = token;
        localStorage.setItem('authToken', token);
    }

    getHeaders() {
        const headers = {
            'Content-Type': 'application/json',
        };
        
        if (this.token) {
            headers['Authorization'] = `Bearer ${this.token}`;
        }
        
        return headers;
    }

    async request(endpoint, options = {}) {
        const url = `${API_BASE_URL}${endpoint}`;
        const config = {
            headers: this.getHeaders(),
            ...options
        };

        try {
            const response = await fetch(url, config);
            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || 'API request failed');
            }

            return data;
        } catch (error) {
            console.error('API Error:', error);
            throw error;
        }
    }

    // Auth methods
    async register(userData) {
        return this.request('/auth/register', {
            method: 'POST',
            body: JSON.stringify(userData)
        });
    }

    async login(credentials) {
        return this.request('/auth/login', {
            method: 'POST',
            body: JSON.stringify(credentials)
        });
    }

    // Medicine methods
    async getMedicines() {
        return this.request('/medicines');
    }

    async getMedicine(id) {
        return this.request(`/medicines/${id}`);
    }

    async addMedicine(medicineData) {
        return this.request('/medicines', {
            method: 'POST',
            body: JSON.stringify(medicineData)
        });
    }

    async updateMedicine(id, medicineData) {
        return this.request(`/medicines/${id}`, {
            method: 'PUT',
            body: JSON.stringify(medicineData)
        });
    }

    async deleteMedicine(id) {
        return this.request(`/medicines/${id}`, {
            method: 'DELETE'
        });
    }

    // Order methods
    async createOrder(orderData) {
        return this.request('/orders', {
            method: 'POST',
            body: JSON.stringify(orderData)
        });
    }

    async getOrders() {
        return this.request('/orders');
    }

    async getOrder(orderId) {
        return this.request(`/orders/${orderId}`);
    }

    async updateOrderStatus(orderId, status) {
        return this.request(`/orders/${orderId}/status`, {
            method: 'PUT',
            body: JSON.stringify({ orderStatus: status })
        });
    }

    // Dashboard methods
    async getDashboardStats() {
        return this.request('/dashboard/stats');
    }
}

// Create global API instance
const apiService = new ApiService();