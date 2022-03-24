Rails.application.routes.draw do
 root 'pages#index'
 resources :questions do 
   resources :answers, only: %i[create destroy edit update]
 end
end
