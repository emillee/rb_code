# user.rb
# ----------------------------------------------------------------------------------------
class User < ActiveRecord::Base
  has_many :identities, dependent: :destroy, inverse_of: :user
  has_many :projects, through: :user_projects, source: :project
  has_many :oauth_contacts
  has_many :wepay_payment_approvals, class_name: 'WepayPaymentApproval', foreign_key: :backer_id
  has_many :projects_invested_in, through: :wepay_payment_approvals, source: :project
  has_many :connections

  has_attached_file :avatar, :path => "/:class/avatars/:id_:basename.:style.:extension"
  validates_attachment_content_type :avatar, content_type: /\Aimage\/.*\Z/

  attr_reader :password
  VALID_EMAIL_REGEX = /\A[\w+\-.]+@[a-z\d\-.]+\.[a-z]+\z/i

  validates :email, presence: true, format: { with: VALID_EMAIL_REGEX }, uniqueness: { case_sensitive: false }
  validates :github_login, uniqueness: true, case_sensitive: false, allow_nil: true
  validates :password, length: { minimum: 6 }, allow_nil: true 

  before_create :create_session_token
  after_save :check_if_prospect_or_member
  
  accepts_nested_attributes_for :identities, allow_destroy: true
  
  scope :admins,    -> { where(is_admin: true) }
  scope :members,   -> { where(is_member: true) }
  scope :prospects, -> { where(is_prospect: true) }

  #-----------------------------------------------------------------------------------------
  # Instance Methods
  #-----------------------------------------------------------------------------------------        

  def administered_project_ids
    self.created_projects.map(&:id)
  end

  #-----------------------------------------------------------------------------------------

  def user_project(project)
    self.user_projects.where(project: project).first
  end  

  #-----------------------------------------------------------------------------------------

  def password=(password_string)
    @password = password_string # for password length validation
    self.password_digest = BCrypt::Password.create(password_string)
  end    

  #-----------------------------------------------------------------------------------------
  # Class Methods
  #-----------------------------------------------------------------------------------------        

  def self.return_emails
    emails = self.all.map(&:email).flatten
    emails.uniq
  end  

  #-----------------------------------------------------------------------------------------

  def followed_projects
    self.connections.where(type_of: 'follower').map(&:project)
  end

  def precommitted_projects
    self.connections.where(type_of: 'precommitted').map(&:project)
  end


#-----------------------------------------------------------------------------------------
# Private
#-----------------------------------------------------------------------------------------        
private

  def check_if_prospect_or_member
    ChangeUserStatusIfPasswordOrIdentity.call(self)
  end

  #-----------------------------------------------------------------------------------------        

  def create_session_token
    self.session_token = SecureRandom.urlsafe_base64
  end

end


# interact with third-party APIs
# ----------------------------------------------------------------------------------------
class ApiRoutesController < ApplicationController
  skip_after_action :verify_authorized

  #-----------------------------------------------------------------------------------------
  # Box
  #-----------------------------------------------------------------------------------------  

  def get_box_view_url
    project = Project.find(params[:project_id])
    headers = { "Authorization" => "Token #{ENV['BOX_VIEW_API_ID']}", "Content-Type" => "application/json" }
    body = { "url" => "#{project.pitchdeck.expiring_url}" }.to_json
    @response = HTTParty.post('https://view-api.box.com/1/documents', headers: headers, body: body)
    
    if @response.code == 202 
      res = JSON.parse(@response.body)
      project.update_attributes(box_api_doc_id: res['id'])
    end

    render json: { response: @response }
  end

  #-----------------------------------------------------------------------------------------  

  def return_box_view_link
    doc_id = params[:doc_id].to_s
    headers = { "Authorization" => "Token #{ENV['BOX_VIEW_API_ID']}", "Content-Type" => "application/json" }
    body = { "document_id" => doc_id, "duration" => '60' }.to_json
    @response = HTTParty.post('https://view-api.box.com/1/sessions', headers: headers, body: body)
    render json: { response: @response }
  end 

  #-----------------------------------------------------------------------------------------
  # Post Tweet or Send DM
  #-----------------------------------------------------------------------------------------    

  def send_twitter_message
    if params[:method] == 'dm'
      tweet_sent = TwitterDm.send_direct_message(current_user, params['screenName'], params['tweetBody'])
      if !!tweet_sent
        respond_to do |format|
          format.json { render json: '', status: :ok }
        end
      else
        format.json { render json: 'no results', status: :unprocessable_entity }
      end
    elsif params[:method] == 'tweet'
      if PostTweet(current_user, params['tweetBody'])
        format.json { head :ok }
      else
        format.json { render json: 'no results', status: :unprocessable_entity }
      end     
    end
  end  

  #-----------------------------------------------------------------------------------------
  # Send Linkedin Message
  #-----------------------------------------------------------------------------------------      

  def send_linked_message
    headers = {'Content-Type' => 'application/json'}
    payload = { 
      'recipients' => 
      { 'values' => 
        [{'person' => 
          { '_path' => "/people/#{params[:linkedin_id]}" } 
        }]
      }, 
      'subject' => params[:subject], 
      'body' => params[:body] }.to_json 
    base_url = "https://api.linkedin.com/v1/people/~/mailbox?oauth2_access_token="
    li_oauth_token = current_user.identities.where(provider: 'linkedin').first.oauth_token
    li_url = base_url + li_oauth_token

    response = HTTParty.post(
      li_url, { body: payload, headers: headers }
    )
  end  

end

# Service Objects
# ----------------------------------------------------------------------------------------
class PostTweet

  def self.call(current_user, tweet_body)
    identity = current_user.identities.where(provider: 'twitter').first

    if identity
      twitter_client = Twitter::REST::Client.new do |config|
        config.consumer_key = ENV["TWITTER_KEY"]
        config.consumer_secret = ENV["TWITTER_SECRET"]
        config.access_token = identity.oauth_token
        config.access_token_secret = identity.oauth_secret
      end

      post_tweet = twitter_client.update(tweet_body)
    end    
  end

end

# ------

class TwitterDm

  def self.send_direct_message(current_user, screen_name, msg_body)
    identity = current_user.identities.where(provider: 'twitter').first

    if identity
      twitter_client = Twitter::REST::Client.new do |config|
        config.consumer_key = ENV["TWITTER_KEY"]
        config.consumer_secret = ENV["TWITTER_SECRET"]
        config.access_token = identity.oauth_token
        config.access_token_secret = identity.oauth_secret
      end

      send_tweet = twitter_client.create_direct_message(screen_name, msg_body)
    end
  end

end

# Roles based authorization
# ----------------------------------------------------------------------------------------
class MessagePolicy < ApplicationPolicy

  def initialize(user, message)
    @user = user
    @message = message
  end  

  def create?
    @message.author == @user && 
    (@message.author.is_member || @message.author.is_admin)
  end

  def update?
    @user.is_admin || @message.author == @user
  end

  def destroy?
    @user.is_admin || @message.author == @user
  end  

  # ------------------------------------------------------------------------------------------

  class Scope
    def initialize(user, scope)
      @user = user
      @scope = scope
    end

    def resolve
      if @user.is_admin
        @scope.all
      else
        # something
        @scope.where(@user.is_member)
      end
    end
  end

end

# rake tasks
# ----------------------------------------------------------------------------------------
desc "PG Backup"
namespace :pg do
  task backup: [:environment] do
    # stamp the filename
    datestamp = Time.now.strftime("%Y-%m-%d_%H-%M-%S")

    # drop it in the db/backups directory temporarily
    backup_file = "#{Rails.root}/db/backups/db_name_#{datestamp}_dump.sql.gz"

    # dump the backup and zip it out
    sh "pg_dump -h localhost -U nytech nytech_development | gzip -c > #{backup_file}"

    send_to_amazon backup_file
  end
end

def send_to_amazon(file_path)
  bucket_name = ENV['S3_BUCKET_NAME']
  key = File.basename(file_path)

  s3 = AWS::S3.new(
    access_key_id: ENV['AWS_ACCESS_KEY'],
    secret_access_key: ENV['AWS_SECRET_ACCESS_KEY']
  )

  s3.buckets[bucket_name].objects[key].write(file: File.open("#{file_path}"))
end

# --
namespace :heroku do 

  desc "deploy production app to heroku"
  task :deploy_production do 
    deploy 'hackerscollective'
  end

  desc "deploy staging app to heroku"
  task :deploy_staging do
    deploy "hackerscollective-staging"
  end
end

def deploy(app)
  system "RAILS_ENV=production bundle exec rake assets:precompile"
  system "git add -f public/assets"
  system 'git commit -m "vendor compiled assets"' 
  
  remote = "git@heroku.com:#{app}.git"
  system "git push -f #{remote} HEAD:master"
  system "heroku maintenance:on --app #{app}"
  system "heroku run rake db:migrate --app #{app}"
  system "heroku restart --app #{app}"
  system "heroku maintenance:off --app #{app}"
end