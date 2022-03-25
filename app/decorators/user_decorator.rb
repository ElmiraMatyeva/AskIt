class UserDecorator < ApplicationDecorator
  delegate_all

  def name_or_email
   name if name.present?

    email.split('@')[0]
  end

end
