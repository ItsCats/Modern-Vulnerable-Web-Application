# Modern Vulnerable Web Application

This project is an intentionally vulnerable web application designed as an educational tool for learning about common web security vulnerabilities. It provides hands-on demonstrations of various attack vectors and their potential impact.

## Vulnerabilities Demonstrated

The application currently includes demonstrations for the following vulnerabilities:

* SQL Injection
* Cross-Site Scripting (XSS)
* Cross-Site Request Forgery (CSRF)
* Insecure Direct Object References (IDOR)
* Path Traversal (Directory Traversal)
* Command Injection
* Simulated Denial of Service (DoS)

## How to Use

1.  **Clone the repository** to your local machine:
    ```bash
    git clone <repository-url>
    ```
    (Replace `<repository-url>` with the URL of your GitHub repository)

2.  **Open the HTML files** in your web browser to explore each vulnerability. The navigation bar in the header will allow you to switch between the different demonstrations.

3.  **Follow the instructions and try the suggested attacks** on each page to understand how the vulnerabilities can be exploited.

4.  **Note:** The "Simulated DoS" page demonstrates the *effects* of a DoS attack on your browser by consuming resources. It does not perform a real attack.

## Deployment

This application is built entirely with client-side HTML, CSS, and JavaScript, making it easy to deploy on static site hosting platforms like Netlify.

1.  **Push your code to a Git repository** (e.g., GitHub, GitLab, Bitbucket).
2.  **Sign up for a free account on [Netlify](https://www.netlify.com/).**
3.  **Connect your Git repository to Netlify** by selecting "Add new site" -> "Deploy with Git".
4.  **Choose your Git provider and select your repository.**
5.  **Configure the deploy settings** (usually, the defaults work for static sites).
6.  **Deploy your site.** Netlify will provide you with a live URL.
