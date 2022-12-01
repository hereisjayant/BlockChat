import React from "react";

class PasswordForm extends React.Component {
    constructor(props) {
        super(props);
        this.state = { value: '' };
        this.authCallback = props.authCallback;

        this.handleChange = this.handleChange.bind(this);
        this.handleSubmit = this.handleSubmit.bind(this);
        this.previouslySet = this.previouslySet.bind(this);
        this.checkPassword = this.checkPassword.bind(this);
        this.setPassword = this.setPassword.bind(this);
    };

    handleChange(event) {
        this.setState({ value: event.target.value });
    };

    async previouslySet() {
        var response = await fetch('/chat/passwordPreviouslySet', {
            method: 'POST',
            body: JSON.stringify({ password: this.state.value })
        });
        if (response.status == 200)
            return true;
        else
            return false;
    };

    async checkPassword() {
        var response = await fetch('/chat/checkPassword', {
            method: 'POST',
            body: JSON.stringify({ password: this.state.value })
        });
        if (response.status == 200)
            return true;
        else
            return false;
    }

    async setPassword() {
        var response = await fetch('/chat/setPassword', {
            method: 'POST',
            body: JSON.stringify({ password: this.state.value })
        });
    }

    handleSubmit(event) {
        //alert('A Password was submitted: ' + this.state.value);
        console.log("submit clicked")
        if (this.previouslySet() && this.checkPassword()) {
            this.authCallback()
        } else if (!this.previouslySet()) {
            this.setPassword();
            this.authCallback()
        } else {
            alert('Password is incorrect')
        }
    
        event.preventDefault();
    }

    render() {
        return (
            <form onSubmit={this.handleSubmit}>
                <label>
                    Password:
                    <input type="text" value={this.state.value} onChange={this.handleChange} />
                </label>
                <input type="submit" value="Submit" />
            </form>
        );
    }
}

export default PasswordForm