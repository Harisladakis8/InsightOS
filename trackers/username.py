import requests
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Tuple
import re

class UsernameTracker:
    def __init__(self):
        self.platforms = {
            "Instagram": {
                "url": "https://www.instagram.com/{}",
                "checker": self._check_instagram,
                "requires_at": False
            },
            "Twitter / X": {
                "url": "https://x.com/{}",
                "checker": self._check_twitter,
                "requires_at": False
            },
            "Facebook": {
                "url": "https://www.facebook.com/{}",
                "checker": self._check_facebook,
                "requires_at": False
            },
            "GitHub": {
                "url": "https://github.com/{}",
                "checker": self._check_github,
                "requires_at": False
            },
            "Reddit": {
                "url": "https://www.reddit.com/user/{}",
                "checker": self._check_reddit,
                "requires_at": False
            },
            "TikTok": {
                "url": "https://www.tiktok.com/@{}",
                "checker": self._check_tiktok,
                "requires_at": True  # TikTok uses @username
            },
            "YouTube": {
                "url": "https://www.youtube.com/@{}",
                "checker": self._check_youtube,
                "requires_at": True
            },
            "Pinterest": {
                "url": "https://www.pinterest.com/{}",
                "checker": self._check_pinterest,
                "requires_at": False
            },
            "Medium": {
                "url": "https://medium.com/@{}",
                "checker": self._check_medium,
                "requires_at": True
            },
            "Steam": {
                "url": "https://steamcommunity.com/id/{}",
                "checker": self._check_steam,
                "requires_at": False
            },
            "Twitch": {
                "url": "https://www.twitch.tv/{}",
                "checker": self._check_twitch,
                "requires_at": False
            },
            "LinkedIn": {
                "url": "https://www.linkedin.com/in/{}",
                "checker": self._check_linkedin,
                "requires_at": False
            },
            "Snapchat": {
                "url": "https://www.snapchat.com/add/{}",
                "checker": self._check_snapchat,
                "requires_at": False
            },
            "Spotify": {
                "url": "https://open.spotify.com/user/{}",
                "checker": self._check_spotify,
                "requires_at": False
            },
            "Discord": {
                "url": "https://discord.com/users/{}",
                "checker": self._check_discord,
                "requires_at": False,
                "note": "Discord uses user IDs, not usernames"
            },
            "GitLab": {
                "url": "https://gitlab.com/{}",
                "checker": self._check_gitlab,
                "requires_at": False
            },
            "Bitbucket": {
                "url": "https://bitbucket.org/{}",
                "checker": self._check_bitbucket,
                "requires_at": False
            }
        }
        
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "DNT": "1",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1"
        }
        
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        
    def _clean_username(self, username: str, platform: str) -> str:
        """Clean username based on platform requirements."""
        username = username.strip()
        
        # Remove @ symbol if present
        if username.startswith('@'):
            username = username[1:]
        
        # Platforms that require @ in URL but not in checking
        if self.platforms[platform]["requires_at"]:
            # The URL already has @, so we return clean username
            pass
        
        return username
    
    def _check_instagram(self, username: str) -> Tuple[bool, Dict]:
        """Check if Instagram account exists."""
        try:
            url = f"https://www.instagram.com/{username}/"
            response = self.session.get(url, timeout=10, allow_redirects=False)
            
            # Instagram returns 200 for both existing and non-existing accounts
            # So we need to check the content
            if response.status_code == 200:
                # Check for signs of "not found" page
                content = response.text.lower()
                
                # Common patterns in Instagram's "not found" page
                not_found_indicators = [
                    'sorry, this page isn\'t available',
                    'the link you followed may be broken',
                    'page not found',
                    'this account doesn\'t exist'
                ]
                
                for indicator in not_found_indicators:
                    if indicator in content:
                        return False, {"status_code": 200, "method": "content_analysis"}
                
                # If we get here, account likely exists
                return True, {"status_code": 200, "url": url}
            
            elif response.status_code == 404:
                return False, {"status_code": 404}
            else:
                return False, {"status_code": response.status_code}
                
        except Exception as e:
            return False, {"error": str(e)}
    
    def _check_twitter(self, username: str) -> Tuple[bool, Dict]:
        """Check if Twitter/X account exists."""
        try:
            url = f"https://x.com/{username}"
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                content = response.text.lower()
                
                # Twitter shows "This account doesn't exist" for non-existent accounts
                if 'this account doesn\'t exist' in content:
                    return False, {"status_code": 200, "method": "content_analysis"}
                
                return True, {"status_code": 200, "url": url}
            
            return False, {"status_code": response.status_code}
                
        except Exception as e:
            return False, {"error": str(e)}
    
    def _check_facebook(self, username: str) -> Tuple[bool, Dict]:
        """Check if Facebook profile exists."""
        try:
            url = f"https://www.facebook.com/{username}"
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                content = response.text.lower()
                
                # Facebook shows "This content isn't available" for non-existent profiles
                if 'this content isn\'t available' in content or 'page not found' in content:
                    return False, {"status_code": 200, "method": "content_analysis"}
                
                return True, {"status_code": 200, "url": url}
            elif response.status_code == 404:
                return False, {"status_code": 404}
            else:
                return False, {"status_code": response.status_code}
                
        except Exception as e:
            return False, {"error": str(e)}
    
    def _check_github(self, username: str) -> Tuple[bool, Dict]:
        """Check if GitHub account exists."""
        try:
            url = f"https://api.github.com/users/{username}"
            headers = {
                "Accept": "application/vnd.github.v3+json",
                "User-Agent": "OSINT-Tracker"
            }
            response = self.session.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                return True, {
                    "status_code": 200,
                    "name": data.get("name"),
                    "followers": data.get("followers"),
                    "public_repos": data.get("public_repos")
                }
            elif response.status_code == 404:
                return False, {"status_code": 404}
            else:
                return False, {"status_code": response.status_code}
                
        except Exception as e:
            return False, {"error": str(e)}
    
    def _check_reddit(self, username: str) -> Tuple[bool, Dict]:
        """Check if Reddit account exists."""
        try:
            url = f"https://www.reddit.com/user/{username}/about.json"
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if "error" not in data:
                    return True, {
                        "status_code": 200,
                        "karma": data.get("data", {}).get("total_karma"),
                        "created": data.get("data", {}).get("created_utc")
                    }
                return False, {"status_code": 200, "error": "User not found in response"}
            elif response.status_code == 404:
                return False, {"status_code": 404}
            else:
                return False, {"status_code": response.status_code}
                
        except Exception as e:
            return False, {"error": str(e)}
    
    def _check_tiktok(self, username: str) -> Tuple[bool, Dict]:
        """Check if TikTok account exists."""
        try:
            url = f"https://www.tiktok.com/@{username}"
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                content = response.text.lower()
                
                # TikTok shows "Couldn't find this account" for non-existent accounts
                if 'couldn\'t find this account' in content or 'page not found' in content:
                    return False, {"status_code": 200, "method": "content_analysis"}
                
                return True, {"status_code": 200, "url": url}
            elif response.status_code == 404:
                return False, {"status_code": 404}
            else:
                return False, {"status_code": response.status_code}
                
        except Exception as e:
            return False, {"error": str(e)}
    
    def _check_youtube(self, username: str) -> Tuple[bool, Dict]:
        """Check if YouTube channel exists."""
        try:
            url = f"https://www.youtube.com/@{username}"
            response = self.session.get(url, timeout=10, allow_redirects=True)
            
            if response.status_code == 200:
                content = response.text.lower()
                
                # YouTube redirects to homepage or shows error for non-existent channels
                final_url = response.url
                if 'c/about' in final_url or 'handle not found' in content:
                    return False, {
                        "status_code": 200, 
                        "method": "url_analysis",
                        "final_url": final_url
                    }
                
                return True, {"status_code": 200, "url": final_url}
            else:
                return False, {"status_code": response.status_code}
                
        except Exception as e:
            return False, {"error": str(e)}
    
    def _check_pinterest(self, username: str) -> Tuple[bool, Dict]:
        """Check if Pinterest account exists."""
        try:
            url = f"https://www.pinterest.com/{username}/"
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                content = response.text.lower()
                
                # Pinterest shows "Sorry, we couldn't find that page"
                if 'sorry, we couldn\'t find that page' in content:
                    return False, {"status_code": 200, "method": "content_analysis"}
                
                return True, {"status_code": 200, "url": url}
            elif response.status_code == 404:
                return False, {"status_code": 404}
            else:
                return False, {"status_code": response.status_code}
                
        except Exception as e:
            return False, {"error": str(e)}
    
    def _check_medium(self, username: str) -> Tuple[bool, Dict]:
        """Check if Medium account exists."""
        try:
            url = f"https://medium.com/@{username}"
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                content = response.text.lower()
                
                # Medium shows "404" in title for non-existent accounts
                if '<title>404' in content or 'page not found' in content:
                    return False, {"status_code": 200, "method": "content_analysis"}
                
                return True, {"status_code": 200, "url": url}
            elif response.status_code == 404:
                return False, {"status_code": 404}
            else:
                return False, {"status_code": response.status_code}
                
        except Exception as e:
            return False, {"error": str(e)}
    
    def _check_steam(self, username: str) -> Tuple[bool, Dict]:
        """Check if Steam profile exists."""
        try:
            url = f"https://steamcommunity.com/id/{username}"
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                content = response.text.lower()
                
                # Steam shows "The specified profile could not be found"
                if 'the specified profile could not be found' in content:
                    return False, {"status_code": 200, "method": "content_analysis"}
                
                return True, {"status_code": 200, "url": url}
            elif response.status_code == 404:
                return False, {"status_code": 404}
            else:
                return False, {"status_code": response.status_code}
                
        except Exception as e:
            return False, {"error": str(e)}
    
    def _check_twitch(self, username: str) -> Tuple[bool, Dict]:
        """Check if Twitch channel exists."""
        try:
            url = f"https://www.twitch.tv/{username}"
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                content = response.text.lower()
                
                # Twitch shows "Sorry. Unless you've got a time machine, that content is unavailable."
                if 'content is unavailable' in content or 'page not found' in content:
                    return False, {"status_code": 200, "method": "content_analysis"}
                
                return True, {"status_code": 200, "url": url}
            elif response.status_code == 404:
                return False, {"status_code": 404}
            else:
                return False, {"status_code": response.status_code}
                
        except Exception as e:
            return False, {"error": str(e)}
    
    def _check_linkedin(self, username: str) -> Tuple[bool, Dict]:
        """Check if LinkedIn profile exists."""
        try:
            url = f"https://www.linkedin.com/in/{username}"
            response = self.session.get(url, timeout=10)
            
            # LinkedIn often requires authentication, so we check for common patterns
            if response.status_code in [200, 999]:
                content = response.text.lower()
                
                # LinkedIn shows login page or "This profile is not available"
                if 'this profile is not available' in content or 'sign in' in content:
                    return False, {
                        "status_code": response.status_code,
                        "method": "content_analysis",
                        "note": "LinkedIn often requires login"
                    }
                
                return True, {"status_code": response.status_code, "url": url}
            else:
                return False, {"status_code": response.status_code}
                
        except Exception as e:
            return False, {"error": str(e)}
    
    def _check_snapchat(self, username: str) -> Tuple[bool, Dict]:
        """Check if Snapchat account exists (limited checking)."""
        try:
            url = f"https://www.snapchat.com/add/{username}"
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                # Snapchat doesn't easily reveal if user exists via web
                # We'll assume it exists if we get 200
                return True, {"status_code": 200, "url": url}
            else:
                return False, {"status_code": response.status_code}
                
        except Exception as e:
            return False, {"error": str(e)}
    
    def _check_spotify(self, username: str) -> Tuple[bool, Dict]:
        """Check if Spotify profile exists."""
        try:
            url = f"https://open.spotify.com/user/{username}"
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                content = response.text.lower()
                
                # Spotify shows "Couldn't find that user" for non-existent profiles
                if 'couldn\'t find that user' in content or 'page not found' in content:
                    return False, {"status_code": 200, "method": "content_analysis"}
                
                return True, {"status_code": 200, "url": url}
            elif response.status_code == 404:
                return False, {"status_code": 404}
            else:
                return False, {"status_code": response.status_code}
                
        except Exception as e:
            return False, {"error": str(e)}
    
    def _check_discord(self, username: str) -> Tuple[bool, Dict]:
        """Check Discord (note: Discord uses IDs, not traditional usernames)."""
        # Discord doesn't have public web profiles for usernames
        return False, {"note": "Discord uses user IDs, not public usernames"}
    
    def _check_gitlab(self, username: str) -> Tuple[bool, Dict]:
        """Check if GitLab account exists."""
        try:
            url = f"https://gitlab.com/{username}"
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                return True, {"status_code": 200, "url": url}
            elif response.status_code == 404:
                return False, {"status_code": 404}
            else:
                return False, {"status_code": response.status_code}
                
        except Exception as e:
            return False, {"error": str(e)}
    
    def _check_bitbucket(self, username: str) -> Tuple[bool, Dict]:
        """Check if Bitbucket account exists."""
        try:
            url = f"https://bitbucket.org/{username}/"
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                return True, {"status_code": 200, "url": url}
            elif response.status_code == 404:
                return False, {"status_code": 404}
            else:
                return False, {"status_code": response.status_code}
                
        except Exception as e:
            return False, {"error": str(e)}
    
    def check_platform(self, platform: str, username: str) -> Dict:
        """Check a single platform."""
        cleaned_username = self._clean_username(username, platform)
        platform_info = self.platforms[platform]
        
        try:
            exists, details = platform_info["checker"](cleaned_username)
            
            result = {
                "platform": platform,
                "username": cleaned_username,
                "exists": exists,
                "url": platform_info["url"].format(cleaned_username),
                "details": details
            }
            
            return result
            
        except Exception as e:
            return {
                "platform": platform,
                "username": cleaned_username,
                "exists": False,
                "url": platform_info["url"].format(cleaned_username),
                "error": str(e),
                "details": {"error": str(e)}
            }
    
    def track_username(self, username: str, max_workers: int = 5) -> Dict:
        """Track username across all platforms with parallel execution."""
        results = {
            "username": username,
            "timestamp": time.time(),
            "platforms_checked": [],
            "found_accounts": [],
            "not_found_accounts": [],
            "errors": []
        }
        
        # Use thread pool for parallel execution
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all platform checks
            future_to_platform = {
                executor.submit(self.check_platform, platform, username): platform
                for platform in self.platforms.keys()
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_platform):
                platform = future_to_platform[future]
                try:
                    platform_result = future.result(timeout=15)
                    results["platforms_checked"].append(platform_result)
                    
                    if platform_result["exists"]:
                        results["found_accounts"].append({
                            "platform": platform,
                            "url": platform_result["url"],
                            "details": platform_result["details"]
                        })
                    else:
                        results["not_found_accounts"].append({
                            "platform": platform,
                            "url": platform_result["url"],
                            "details": platform_result.get("details", {}),
                            "error": platform_result.get("error")
                        })
                        
                except Exception as e:
                    error_result = {
                        "platform": platform,
                        "username": username,
                        "exists": False,
                        "error": str(e),
                        "url": self.platforms[platform]["url"].format(username)
                    }
                    results["platforms_checked"].append(error_result)
                    results["errors"].append({
                        "platform": platform,
                        "error": str(e)
                    })
                    results["not_found_accounts"].append({
                        "platform": platform,
                        "url": self.platforms[platform]["url"].format(username),
                        "error": str(e)
                    })
        
        # Calculate statistics
        results["found_count"] = len(results["found_accounts"])
        results["total_checked"] = len(self.platforms)
        results["success_rate"] = f"{(results['found_count'] / results['total_checked'] * 100):.1f}%" if results['total_checked'] > 0 else "0%"
        
        # Add summary
        results["summary"] = {
            "username": username,
            "found_on": [acc["platform"] for acc in results["found_accounts"]],
            "not_found_on": [acc["platform"] for acc in results["not_found_accounts"]],
            "total_platforms": results["total_checked"],
            "platforms_found": results["found_count"],
            "platforms_not_found": len(results["not_found_accounts"]),
            "errors": len(results["errors"])
        }
        
        return results

# Backward compatibility function
def username_tracker(username: str) -> dict:
    """Legacy function for compatibility with existing code."""
    tracker = UsernameTracker()
    results = tracker.track_username(username)
    
    # Format for backward compatibility
    return {
        "username": results["username"],
        "found_accounts": [acc["platform"] for acc in results["found_accounts"]],
        "not_found_accounts": [acc["platform"] for acc in results["not_found_accounts"]],
        "found_count": results["found_count"],
        "checked_platforms": results["total_checked"],
        "detailed_results": results["platforms_checked"],
        "summary": results["summary"],
        "timestamp": results["timestamp"]
    }


# Example usage
if __name__ == "__main__":
    # Test the tracker
    tracker = UsernameTracker()
    
    # Test with a username
    username = "github"  # Change this to test different usernames
    print(f"Tracking username: {username}")
    print("-" * 50)
    
    results = tracker.track_username(username)
    
    print(f"Username: {results['username']}")
    print(f"Found on {results['found_count']} out of {results['total_checked']} platforms")
    print(f"Success rate: {results['success_rate']}")
    print("\nFound accounts:")
    for account in results["found_accounts"]:
        print(f"  • {account['platform']}: {account['url']}")
    
    print("\nNot found on:")
    for account in results["not_found_accounts"][:10]:  # Show first 10
        print(f"  • {account['platform']}")
    
    if len(results["not_found_accounts"]) > 10:
        print(f"  ... and {len(results['not_found_accounts']) - 10} more platforms")
