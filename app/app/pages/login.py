from __future__ import annotations

import typing as t
from dataclasses import KW_ONLY, field

import re
import pyotp

import rio

from app.persistence import Persistence
from app.data_models import AppUser, UserSettings
from app.components.center_component import CenterComponent


def guard(event: rio.GuardEvent) -> str | None:
    """
    A guard which only allows the user to access this page if they are not
    logged in yet. If the user is already logged in, the login page will be
    skipped and the user will be redirected to the home page instead.
    """
    # Check if the user is authenticated by looking for a user session
    try:
        event.session[AppUser]

    # User is not logged in, no redirection needed
    except KeyError:
        return None

    # User is logged in, redirect to the home page
    return "/home"







def get_password_strength(password) -> int:

    password
    """
    Calculate the strength of a given password based on various criteria
    and return a score between 0 and 100.
    """
    
    length = len(password)
    score = 0
    
    # Additions
    score += length * 4
    
    # Check for different character types
    upper_case_letters = re.findall(r'[A-Z]', password)
    lower_case_letters = re.findall(r'[a-z]', password)
    numbers = re.findall(r'\d', password)
    symbols = re.findall(r'[\W_]', password)  # Non-alphanumeric characters

    if upper_case_letters:
        score += (length - len(upper_case_letters)) * 2
    if lower_case_letters:
        score += (length - len(lower_case_letters)) * 2
    if numbers:
        score += len(numbers) * 4
    if symbols:
        score += len(symbols) * 6

    # Middle numbers or symbols
    if length > 2:
        middle_chars = password[1:-1]
        middle_numbers_or_symbols = len(re.findall(r'[\d\W_]', middle_chars))
        score += middle_numbers_or_symbols * 2

    # Requirements
    requirements = [
        length >= 12,
        bool(upper_case_letters),
        bool(lower_case_letters),
        bool(numbers),
        bool(symbols)
    ]
    fulfilled_requirements = sum(requirements)
    if fulfilled_requirements >= 3:
        score += fulfilled_requirements * 2

    # Deductions
    if re.match(r'^[a-zA-Z]+$', password):  # Letters only
        score -= length
    if re.match(r'^\d+$', password):  # Numbers only
        score -= length
    
    # Repeat characters (case insensitive)
    repeat_chars = len(password) - len(set(password.lower()))
    score -= repeat_chars
    
    # Consecutive uppercase letters
    consecutive_upper = len(re.findall(r'[A-Z]{2,}', password))
    score -= consecutive_upper * 2
    
    # Consecutive lowercase letters
    consecutive_lower = len(re.findall(r'[a-z]{2,}', password))
    score -= consecutive_lower * 2
    
    # Consecutive numbers
    consecutive_numbers = len(re.findall(r'\d{2,}', password))
    score -= consecutive_numbers * 2
    
    # Sequential letters (3+)
    sequential_letters = sum([1 for i in range(len(password)-2)
                            if password[i:i+3].isalpha() and
                            ord(password[i+1]) == ord(password[i])+1 and
                            ord(password[i+2]) == ord(password[i])+2])
    score -= sequential_letters * 3
    
    # Sequential numbers (3+)
    sequential_numbers = sum([1 for i in range(len(password)-2)
                            if password[i:i+3].isdigit() and
                            ord(password[i+1]) == ord(password[i])+1 and
                            ord(password[i+2]) == ord(password[i])+2])
    score -= sequential_numbers * 3
    
    # Sequential symbols (3+)
    sequential_symbols = sum([1 for i in range(len(password)-2)
                            if re.match(r'[\W_]{3}', password[i:i+3]) and
                            ord(password[i+1]) == ord(password[i])+1 and
                            ord(password[i+2]) == ord(password[i])+2])
    score -= sequential_symbols * 3

    # Ensure score is within bounds
    score = max(0, min(score, 99))

    #self.password_strength = score
    return score


def get_password_strength_color(score):
    # Ensure the score is within the range 0-99
    score = max(0, min(score, 99))
    
    # Calculate the color components
    red = (99 - score) / 99
    green = score / 99
    
    # Return the color
    return rio.Color.from_rgb(red, green, 0)


def get_password_strength_status(score):
    
    # very weak, weak, ok, strong, very strong
    if score < 30:
        return 'very weak'
    elif score < 50:
        return 'weak'
    elif score < 70:
        return 'ok'
    elif score < 90:
        return 'strong'
    else:
        return 'very strong'
    

class UserSignUpForm(rio.Component):
    """
    Provides interface for users to sign up for a new account.

    It includes fields for username and password, handles user creation, and
    displays error messages if the sign-up process fails.
    """

    # This will be set to `True` when the sign-up popup is open
    popup_open: bool

    # These fields will be bound to the input fields in the form. This allows us
    # to easily access the values entered by the user.
    email: str = ""
    password: str = ""
    confirm_password: str = ""



    # This field will be used to display an error message if the sign-up process
    # fails.
    error_message: str = ""

    # These fields will be updated to reflect the validity of the username and
    # passwords entered by the user. If they are invalid, we will display an
    # error message to the user.
    is_email_valid: bool = False
    passwords_valid: bool = False

    password_strength: int = 0
    do_passwords_match: bool = False
    is_email_taken: bool = False

    async def on_sign_up_pressed(self) -> None:
        """
        Handles the sign-up process when the user submits the sign-up form.

        It will check if the user already exists and if the passwords match. If
        the user does not exist and the passwords match, a new user will be
        created and stored in the database.
        """
        # Get the persistence instance. It was attached to the session earlier,
        # so we can easily access it from anywhere.
        pers = self.session[Persistence]

        # Make sure all fields are populated
        if (
            not self.email
            or not self.password
            or not self.confirm_password
        ):
            self.error_message = "Please fill in all fields"
            self.passwords_valid = False
            self.is_email_valid = False
            return

        # Check if the passwords match
        if self.password != self.confirm_password:
            self.error_message = "Passwords do not sdfsmatch"
            self.passwords_valid = False
            self.is_email_valid = True
            return

        # Check if this username is available
        try:
            await pers.get_user_by_username(username=self.email)
        except KeyError:
            pass
        else:
            self.error_message = "This username is already taken"
            self.is_email_valid = False
            self.passwords_valid = True
            return

        # Create a new user
        user_info = AppUser.create_new_user_with_default_settings(
            username=self.email,
            password=self.password,
        )

        # Store the user in the database
        await pers.create_user(user_info)

        # Registration is complete - close the popup
        self.popup_open = False


        # CHOOSING TO NOT AUTO LOGIN
        # # Log the user in, so they can start using the app straight away. To do
        # # this, first create a session.
        # user_session = await pers.create_session(
        #     user_id=user_info.id,
        # )

        # # Attach the session and userinfo. This indicates to any other
        # # component in the app that somebody is logged in, and who that is.
        # self.session.attach(user_session)
        # self.session.attach(user_info)

        # # Permanently store the session token with the connected client.
        # # This way they can be recognized again should they reconnect later.
        # settings = self.session[UserSettings]
        # settings.auth_token = user_session.id
        # self.session.attach(settings)

        # The user is logged in - no reason to stay here
        self.session.navigate_to("/app/home")

    def on_cancel(self) -> None:
        """
        Closes the sign-up popup when the user clicks the cancel button.

        It also resets all fields to their default values.
        """
        # Set all fields to default values
        self.is_email_valid: bool = True
        self.passwords_valid: bool = True
        self.email: str = ""
        self.password: str = ""
        self.confirm_password: str = ""
        self.error_message: str = ""

        # Close pop up
        self.popup_open = False




    
    def validate_email(self, email):

        email_regex = r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
        if email != "" and re.match(email_regex, email) is not None:
            self.is_email_valid = True
        else:
            self.is_email_valid = False

    async def update_email(self, event: rio.TextInputChangeEvent):
        self.email = event.text
        self.validate_email(self.email)
        self.force_refresh()
        
    async def update_password(self, event: rio.TextInputChangeEvent):
        self.password = event.text
        self.password_strength = get_password_strength(self.password)
        self.do_passwords_match = self.password == self.confirm_password
        self.force_refresh()
        
    async def update_confirm_password(self, event: rio.TextInputChangeEvent):
        self.confirm_password = event.text
        self.do_passwords_match = self.password == self.confirm_password
        self.force_refresh()
    
    def password_strength_progress(self):
        
        return rio.ProgressBar(
            progress=max(0, min(self.password_strength/100, 1)),
            color=get_password_strength_color(self.password_strength),
        )



    def build(self) -> rio.Component:
        return rio.Card(
            rio.Column(
                # Heading
                rio.Text("Create account", style="heading1"),
                # Display an error, if any
                rio.Banner(
                    text=self.error_message,
                    style="danger",
                    margin_top=1,
                ),
                
                
                rio.TextInput(
                    text=self.email,
                    label="Email",
                    on_change=self.update_email,
                    is_sensitive=True
                ),
                
                rio.TextInput(
                    text=self.password,
                    label="Password",
                    on_change=self.update_password,
                    #is_sensitive=True,
                    is_secret=True
                ),
                
                rio.TextInput(
                    text=self.confirm_password,
                    label="Confirm Password",
                    on_change=self.update_confirm_password,
                    is_sensitive=True,
                    is_secret=True
                ),
            
            
                rio.Text(
                    f'Email is valid: {self.is_email_valid}',
                    style=rio.TextStyle(
                        fill=rio.Color.from_rgb(0, 1, 0) if self.is_email_valid else rio.Color.from_rgb(1, 0, 0)
                    )
                ),
                
                rio.Text(
                    f'Passwords match: {self.do_passwords_match}',
                    style=rio.TextStyle(
                        fill=rio.Color.from_rgb(0, 1, 0) if self.do_passwords_match else rio.Color.from_rgb(1, 0, 0)
                    ),
                ),

                
                rio.Text(
                    f'Password strength: {self.password_strength}, {get_password_strength_status(self.password_strength)}',
                    style=rio.TextStyle(
                        fill=get_password_strength_color(self.password_strength)
                    )
                ),
                
                self.password_strength_progress(),



                
                
                # And finally, some buttons to confirm or cancel the sign-up
                # process
                rio.Row(
                    rio.Button(
                        "Sign up",
                        on_press=self.on_sign_up_pressed,
                        shape='rounded',
                    ),
                    rio.Button(
                        "Cancel",
                        on_press=self.on_cancel,
                        shape='rounded',
                    ),
                    spacing=2,
                ),
                spacing=1,
                margin=2,
            ),
            align_x=0.5,
            align_y=0.5,
            # shadow_radius=3,
        )




@rio.page(
    name="Login",
    url_segment="login",
    guard=guard,
)
class LoginPage(rio.Component):
    """
    Login page for accessing the website.
    """

    # These are used to store the currently entered values from the user
    username: str = ""
    password: str = ""
    verification_code: str = ""
    error_message: str = ""
    popup_open: bool = False

    _currently_logging_in: bool = False

    async def login(self, _: rio.TextInputConfirmEvent | None = None) -> None:
        """
        Handles the login process when the user submits their credentials.

        It will check if the user exists and if the password is correct. If the
        user exists and the password is correct, it will then check if 2FA is enabled.
        If 2FA is enabled, it will verify the provided code before logging in.
        """
        try:
            # Inform the user that something is happening
            self._currently_logging_in = True
            self.force_refresh()

            #  Try to find a user with this name
            pers = self.session[Persistence]

            try:
                user_info = await pers.get_user_by_username(
                    username=self.username
                )
            except KeyError:
                self.error_message = "Invalid username. Please try again or create a new account."
                return

            # Make sure their password matches
            if not user_info.verify_password(self.password):
                self.error_message = "Invalid password. Please try again or create a new account."
                return

            # Check if 2FA is enabled for this user
            if user_info.two_factor_secret:
                # Verify 2FA code if provided
                if not self.verification_code:
                    self.error_message = "2FA is enabled for this account. Please enter your verification code."
                    return
                
                # Verify the TOTP code
                totp = pyotp.TOTP(user_info.two_factor_secret)
                if not totp.verify(self.verification_code):
                    self.error_message = "Invalid verification code. Please try again."
                    return
                print("2FA verification successful")

            # The login was successful
            self.error_message = ""

            # Create and store a session
            user_session = await pers.create_session(
                user_id=user_info.id,
            )

            # Attach the session and userinfo. This indicates to any other
            # component in the app that somebody is logged in, and who that is.
            self.session.attach(user_session)
            self.session.attach(user_info)

            # Permanently store the session token with the connected client.
            # This way they can be recognized again should they reconnect later.
            settings = self.session[UserSettings]
            settings.auth_token = user_session.id
            self.session.attach(settings)

            # The user is logged in - no reason to stay here
            self.session.navigate_to("/app/dashboard")

        # Done
        finally:
            self._currently_logging_in = False

    def on_open_popup(self) -> None:
        """
        Opens the sign-up popup when the user clicks the sign-up button
        """
        self.popup_open = True

    def build(self) -> rio.Component:
        # Create a banner with the error message if there is one

        return CenterComponent(
            rio.Card(
                    rio.Column(
                        rio.Text("Login", style="heading1", justify="center"),
                        # Show error message if there is one
                        #
                        # Banners automatically appear invisible if they don't have
                        # anything to show, so there is no need for a check here.
                        rio.Banner(
                            text=self.error_message,
                        style="danger",
                        margin_top=1,
                    ),
                    # Create the login form consisting of a username and password
                    # input field, a login button and a sign up button
                    rio.TextInput(
                        text=self.bind().username,
                        label="Email/Username",
                        # ensure the login function is called when the user presses enter
                        on_confirm=self.login,
                    ),
                    rio.TextInput(
                        text=self.bind().password,
                        label="Password",
                        # Mark the password field as secret so the password is
                        # hidden while typing
                        is_secret=True,
                        # Ensure the login function is called when the user presses
                        # enter
                        on_confirm=self.login,
                    ),
                    
                    rio.TextInput(
                        text=self.bind().verification_code,
                        label="2FA Code (if applicable)",
                        on_confirm=self.login,
                    ),
                    
                    
                    
                    rio.Row(
                        rio.Button(
                            "Login",
                            on_press=self.login,
                            is_loading=self._currently_logging_in,
                            shape='rounded',
                        ),
                        # Create a sign up button that opens a pop up with a sign up
                        # form
                        rio.Popup(
                            anchor=rio.Button(
                                "Sign up",
                                on_press=self.on_open_popup,
                                shape='rounded',
                            ),
                            content=UserSignUpForm(
                                # Bind `popup_open` to the `popup_open` attribute of
                                # the login page. This way the page's attribute will
                                # always have the same value as that of the form,
                                # even when one changes.
                                popup_open=self.bind().popup_open,
                            ),
                            position="fullscreen",
                            is_open=self.popup_open,
                            color="none",
                        ),
                        spacing=2,
                    ),
                    spacing=1,
                    margin=2,
                ),
                align_x=0.5,
                align_y=0,
            ),
            width_percent=40,
            height_percent=40,
        )
