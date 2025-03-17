/**
 * HR System Chatbot powered by Google Gemini
 * Provides an interactive chat interface for HR-related questions
 */
(function() {
    // DOM Elements
    const chatbot = document.getElementById('hrChatbot');
    if (!chatbot) return; // Exit if chatbot container doesn't exist
    
    const chatbotToggle = document.getElementById('chatbotToggle');
    const chatbotClose = document.getElementById('chatbotClose');
    const chatbotReset = document.getElementById('chatbotReset');
    const chatbotForm = document.getElementById('chatbotForm');
    const chatbotInput = document.getElementById('chatbotInput');
    const chatbotMessages = document.getElementById('chatbotMessages');
    const chatbotSuggestions = document.querySelectorAll('.hr-chatbot-suggestion');
    
    // State
    let isLoading = false;
    
    // Specialized commands that trigger enhanced responses
    const specialCommands = {
        'show my leave balance': fetchLeaveBalance,
        'show leave balance': fetchLeaveBalance,
        'my leaves': fetchPendingLeaves,
        'pending leaves': fetchPendingLeaves,
        'my trainings': fetchUpcomingTrainings,
        'upcoming trainings': fetchUpcomingTrainings
    };
    
    // Check if message is a special command
    function checkForSpecialCommands(message) {
        const normalizedMessage = message.toLowerCase().trim();
        
        for (const [command, handler] of Object.entries(specialCommands)) {
            if (normalizedMessage === command || normalizedMessage.includes(command)) {
                return handler;
            }
        }
        
        return null;
    }
    
    // Special command handlers
    async function fetchLeaveBalance() {
        try {
            const response = await fetch('/api/chatbot/user-info/leave_balance');
            const data = await response.json();
            
            if (data.status === 'success') {
                const message = `
                    <h6>Your Leave Balance</h6>
                    <table class="table table-sm">
                        <tr>
                            <th>Annual Leave</th>
                            <td>${data.annual_leave - data.used_annual} / ${data.annual_leave} days</td>
                        </tr>
                        <tr>
                            <th>Sick Leave</th>
                            <td>${data.sick_leave - data.used_sick} / ${data.sick_leave} days</td>
                        </tr>
                        <tr>
                            <th>Personal Leave</th>
                            <td>${data.personal_leave - data.used_personal} / ${data.personal_leave} days</td>
                        </tr>
                    </table>
                    <p class="mb-0"><small>You can request leave from the <a href="/leaves">Leave Management</a> section.</small></p>
                `;
                
                return message;
            }
        } catch (error) {
            console.error('Error fetching leave balance:', error);
        }
        
        return "I wasn't able to retrieve your leave balance. Please try again later or check the Leave Management section directly.";
    }
    
    async function fetchPendingLeaves() {
        try {
            const response = await fetch('/api/chatbot/user-info/pending_leaves');
            const data = await response.json();
            
            if (data.status === 'success') {
                if (data.leaves.length === 0) {
                    return "You don't have any pending leave requests.";
                }
                
                let message = `<h6>Your Pending Leave Requests</h6><ul>`;
                
                data.leaves.forEach(leave => {
                    message += `
                        <li>
                            ${leave.leave_type.charAt(0).toUpperCase() + leave.leave_type.slice(1)} Leave: 
                            ${leave.start_date} to ${leave.end_date} 
                            (${leave.duration_days} days)
                        </li>
                    `;
                });
                
                message += `</ul><p class="mb-0"><small>You can view all your leave requests in the <a href="/leaves">Leave Management</a> section.</small></p>`;
                
                return message;
            }
        } catch (error) {
            console.error('Error fetching pending leaves:', error);
        }
        
        return "I wasn't able to retrieve your pending leave requests. Please try again later or check the Leave Management section directly.";
    }
    
    async function fetchUpcomingTrainings() {
        try {
            const response = await fetch('/api/chatbot/user-info/upcoming_trainings');
            const data = await response.json();
            
            if (data.status === 'success') {
                if (data.trainings.length === 0) {
                    return "You don't have any upcoming training programs.";
                }
                
                let message = `<h6>Your Upcoming Training Programs</h6><ul>`;
                
                data.trainings.forEach(training => {
                    message += `
                        <li>
                            ${training.title}: 
                            ${training.start_date} to ${training.end_date}
                        </li>
                    `;
                });
                
                message += `</ul><p class="mb-0"><small>You can view all your trainings in the <a href="/trainings/my-enrollments">Training Programs</a> section.</small></p>`;
                
                return message;
            }
        } catch (error) {
            console.error('Error fetching upcoming trainings:', error);
        }
        
        return "I wasn't able to retrieve your upcoming training programs. Please try again later or check the Training Programs section directly.";
    }
    
    /**
     * Toggle chatbot window visibility
     */
    function toggleChatbot() {
        chatbot.classList.toggle('hr-chatbot-open');
        
        // Focus input when opened
        if (chatbot.classList.contains('hr-chatbot-open')) {
            chatbotInput.focus();
            
            // Mark as seen if there were new messages
            chatbot.classList.remove('hr-chatbot-new-message');
        }
    }
    
    /**
     * Add a new message to the chat window
     * @param {string} message - The message text
     * @param {string} sender - 'user' or 'bot'
     */
    function addMessage(message, sender) {
        const messageElement = document.createElement('div');
        messageElement.classList.add('hr-chatbot-message');
        messageElement.classList.add(`hr-chatbot-message-${sender}`);
        
        // Avatar for the message
        const avatarElement = document.createElement('div');
        avatarElement.classList.add('hr-chatbot-message-avatar');
        
        const iconElement = document.createElement('i');
        iconElement.classList.add('fas');
        iconElement.classList.add(sender === 'user' ? 'fa-user' : 'fa-robot');
        avatarElement.appendChild(iconElement);
        
        // Content of the message
        const contentElement = document.createElement('div');
        contentElement.classList.add('hr-chatbot-message-content');
        
        // Parse markdown-like formatting for bot messages
        if (sender === 'bot') {
            // Convert ** for bold
            message = message.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
            
            // Convert * for italic
            message = message.replace(/\*(.*?)\*/g, '<em>$1</em>');
            
            // Convert bullet points
            message = message.replace(/- (.*?)(\n|$)/g, '<li>$1</li>');
            if (message.includes('<li>')) {
                message = '<ul>' + message + '</ul>';
            }
            
            // Handle paragraphs
            message = message.replace(/\n\n/g, '</p><p>');
            message = '<p>' + message + '</p>';
        } else {
            message = '<p>' + message + '</p>';
        }
        
        contentElement.innerHTML = message;
        
        // Assemble and add the message
        messageElement.appendChild(avatarElement);
        messageElement.appendChild(contentElement);
        chatbotMessages.appendChild(messageElement);
        
        // Scroll to bottom
        chatbotMessages.scrollTop = chatbotMessages.scrollHeight;
    }
    
    /**
     * Display a loading indicator while waiting for a response
     */
    function showLoadingIndicator() {
        isLoading = true;
        
        const loadingElement = document.createElement('div');
        loadingElement.classList.add('hr-chatbot-message');
        loadingElement.classList.add('hr-chatbot-message-bot');
        loadingElement.classList.add('hr-chatbot-message-loading');
        loadingElement.id = 'chatbotLoading';
        
        // Avatar for the loading indicator
        const avatarElement = document.createElement('div');
        avatarElement.classList.add('hr-chatbot-message-avatar');
        
        const iconElement = document.createElement('i');
        iconElement.classList.add('fas', 'fa-robot');
        avatarElement.appendChild(iconElement);
        
        // Loading dots
        const contentElement = document.createElement('div');
        contentElement.classList.add('hr-chatbot-message-content');
        
        const dotsElement = document.createElement('div');
        dotsElement.classList.add('hr-chatbot-loading-dots');
        
        for (let i = 0; i < 3; i++) {
            const dot = document.createElement('div');
            dot.classList.add('hr-chatbot-loading-dot');
            dotsElement.appendChild(dot);
        }
        
        contentElement.appendChild(dotsElement);
        
        // Assemble and add the loading indicator
        loadingElement.appendChild(avatarElement);
        loadingElement.appendChild(contentElement);
        chatbotMessages.appendChild(loadingElement);
        
        // Scroll to bottom
        chatbotMessages.scrollTop = chatbotMessages.scrollHeight;
    }
    
    /**
     * Remove loading indicator
     */
    function removeLoadingIndicator() {
        isLoading = false;
        const loadingElement = document.getElementById('chatbotLoading');
        if (loadingElement) {
            loadingElement.remove();
        }
    }
    
    /**
     * Send a message to the chatbot API
     * @param {string} message - The message to send
     */
    async function sendMessage(message) {
        // Don't send empty messages
        if (!message.trim()) return;
        
        // Add user message to chat
        addMessage(message, 'user');
        
        // Clear input
        chatbotInput.value = '';
        
        // Show loading indicator
        showLoadingIndicator();
        
        try {
            // Check for special commands
            const specialCommandHandler = checkForSpecialCommands(message);
            
            if (specialCommandHandler) {
                // Handle special command directly
                const result = await specialCommandHandler();
                removeLoadingIndicator();
                addMessage(result, 'bot');
                return;
            }
            
            // Regular message handling
            const response = await fetch('/api/chatbot/message', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ message }),
            });
            
            const data = await response.json();
            
            // Remove loading indicator
            removeLoadingIndicator();
            
            // Add bot response to chat
            if (data.status === 'success') {
                addMessage(data.message, 'bot');
            } else {
                addMessage("I'm having trouble connecting to my knowledge base. Please try again later.", 'bot');
            }
        } catch (error) {
            console.error('Error sending message to chatbot:', error);
            
            // Remove loading indicator
            removeLoadingIndicator();
            
            // Add error message to chat
            addMessage("Sorry, there was an error. Please try again later.", 'bot');
        }
    }
    
    /**
     * Reset the conversation
     */
    async function resetConversation() {
        try {
            // Clear messages UI first
            chatbotMessages.innerHTML = '';
            
            // Send reset request to API
            const response = await fetch('/api/chatbot/reset', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
            });
            
            const data = await response.json();
            
            // Add welcome message
            addMessage("Hello! I'm your HR Assistant. How can I help you today?", 'bot');
            
        } catch (error) {
            console.error('Error resetting conversation:', error);
            
            // Add error message to chat
            addMessage("Sorry, there was an error resetting the conversation.", 'bot');
        }
    }
    
    /**
     * Event Listeners
     */
    
    // Toggle chatbot visibility
    if (chatbotToggle) {
        chatbotToggle.addEventListener('click', toggleChatbot);
    }
    
    // Close chatbot
    if (chatbotClose) {
        chatbotClose.addEventListener('click', toggleChatbot);
    }
    
    // Reset conversation
    if (chatbotReset) {
        chatbotReset.addEventListener('click', resetConversation);
    }
    
    // Submit message form
    if (chatbotForm) {
        chatbotForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            // Don't allow sending while previous request is loading
            if (isLoading) return;
            
            const message = chatbotInput.value;
            sendMessage(message);
        });
    }
    
    // Quick suggestion buttons
    chatbotSuggestions.forEach(button => {
        button.addEventListener('click', function() {
            const message = this.dataset.message;
            
            // Don't allow sending while previous request is loading
            if (isLoading) return;
            
            sendMessage(message);
        });
    });
    
    // Handle Escape key to close chatbot
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape' && chatbot.classList.contains('hr-chatbot-open')) {
            toggleChatbot();
        }
    });
})();
