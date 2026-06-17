/**
 * SkillGuard - Main JavaScript
 * AI Skill Security Scanner Platform
 */

// Utility functions
const Utils = {
    /**
     * Format file size to human readable string
     */
    formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    },

    /**
     * Format date to local string
     */
    formatDate(dateString) {
        if (!dateString) return '-';
        const date = new Date(dateString);
        return date.toLocaleString('zh-CN');
    },

    /**
     * Escape HTML to prevent XSS
     */
    escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    },

    /**
     * Debounce function
     */
    debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    },

    /**
     * Get status badge HTML
     */
    getStatusBadge(status) {
        const badges = {
            'pending': '<span class="badge bg-secondary">未开始</span>',
            'queued': '<span class="badge bg-info">排队中</span>',
            'running': '<span class="badge bg-warning"><i class="fas fa-spinner fa-spin me-1"></i>进行中</span>',
            'completed': '<span class="badge bg-success">已完成</span>',
            'failed': '<span class="badge bg-danger">扫描失败</span>'
        };
        return badges[status] || `<span class="badge bg-secondary">${status}</span>`;
    },

    /**
     * Get risk level badge HTML
     */
    getRiskBadge(level) {
        const badges = {
            'safe': '<span class="badge bg-success">安全</span>',
            'warning': '<span class="badge bg-warning">警告</span>',
            'dangerous': '<span class="badge bg-orange">危险</span>',
            'high-risk': '<span class="badge bg-danger">高危</span>',
            'unknown': '<span class="badge bg-secondary">未知</span>'
        };
        return badges[level] || `<span class="badge bg-secondary">${level}</span>`;
    },

    /**
     * Get source name
     */
    getSourceName(source) {
        const names = {
            'official': '官方认证',
            'verified': '社区验证',
            'community': '社区贡献'
        };
        return names[source] || source;
    },

    /**
     * Get risk name
     */
    getRiskName(risk) {
        const names = {
            'safe': '安全',
            'warning': '警告',
            'dangerous': '危险',
            'high-risk': '高危'
        };
        return names[risk] || risk;
    },

    /**
     * Get detection method name
     */
    getMethodName(method) {
        const names = {
            'static_analysis': '静态分析',
            'llm_static_review': 'LLM静态审查',
            'static_analysis_fp': '静态分析(误报)',
            'signature_matching': '特征匹配',
            'agent_intel': 'Agent情报研判',
            'signature_matching_fp': '特征匹配(误报)',
            'llm_analysis': 'LLM意图分析',
            'sandbox': '沙箱检测',
            'llm_correlation': 'LLM关联分析'
        };
        if (names[method]) return names[method];
        if (method && method.includes('+')) {
            return method.split('+').map(m => names[m] || m).join(' + ');
        }
        return method;
    },

    /**
     * Show toast notification
     */
    showToast(message, type = 'info') {
        const toast = document.createElement('div');
        toast.className = `alert alert-${type} alert-dismissible fade show position-fixed`;
        toast.style.cssText = 'top: 20px; right: 20px; z-index: 9999; min-width: 300px;';
        toast.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;
        document.body.appendChild(toast);
        
        setTimeout(() => {
            toast.remove();
        }, 5000);
    },

    /**
     * Copy text to clipboard
     */
    async copyToClipboard(text) {
        try {
            await navigator.clipboard.writeText(text);
            this.showToast('已复制到剪贴板', 'success');
        } catch (err) {
            console.error('复制失败:', err);
            this.showToast('复制失败', 'danger');
        }
    }
};

// Global event listeners
document.addEventListener('DOMContentLoaded', function() {
    // Add smooth scrolling
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function(e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });

    // Add loading state to buttons
    document.querySelectorAll('button[data-loading]').forEach(button => {
        button.addEventListener('click', function() {
            const originalText = this.innerHTML;
            const loadingText = this.dataset.loading || '<i class="fas fa-spinner fa-spin me-2"></i>处理中...';
            
            this.innerHTML = loadingText;
            this.disabled = true;
            
            // Reset after 5 seconds if not already reset
            setTimeout(() => {
                if (this.disabled) {
                    this.innerHTML = originalText;
                    this.disabled = false;
                }
            }, 5000);
        });
    });
});

// Export for use in other scripts
window.SkillGuard = window.SkillGuard || {};
window.SkillGuard.Utils = Utils;
