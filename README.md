# Omniauth::Gohighlevel

TODO: Delete this and the text below, and describe your gem

Welcome to your new gem! In this directory, you'll find the files you need to be able to package up your Ruby library into a gem. Put your Ruby code in the file `lib/omniauth/gohighlevel`. To experiment with that code, run `bin/console` for an interactive prompt.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'omniauth-gohighlevel'
```

And then execute:

    $ bundle install

Or install it yourself as:

    $ gem install omniauth-gohighlevel

## Usage

Here's a quick example, adding the middleware to a Rails app in config/initializers/omniauth.rb:

Rails.application.config.middleware.use OmniAuth::Builder do
  provider :gohighlevel, ENV['GOHIGHLEVEL_CLIENT_ID'], ENV['GOHIGHLEVEL_CLIENT_SECRET'], {
    scope: "contacts.write contacts.readonly invoices.readonly invoices.write products.readonly locations.readonly"
  }
end

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake test` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and the created tag, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/michaelkoper/omniauth-gohighlevel.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).