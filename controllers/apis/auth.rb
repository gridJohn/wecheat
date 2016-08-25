require 'securerandom'


class WecheatApp
  get '/connect/oauth2/authorize' do
    if params.keys[0,4] != ["appid", "redirect_uri", "response_type", "scope"]
      json errcode: 99999, errmsg: '参数必须这么来 appid redirect_uri response_type scope [state]'
    elsif params[:response_type] != 'code'
      json errcode: 99999, errmsg: 'response_type 必须是 code'
    elsif params[:scope] == 'snsapi_userinfo'
      json errcode: 99999, errmsg: '现在这个 faker 只能接受 snsapi_base, SORRY'
    elsif params[:scope] != 'snsapi_base'
      json errcode: 99999, errmsg: 'scope 可以是 snsapi_base, snsapi_userinfo'
    elsif !(app = Wecheat::Models::App.find(params[:appid]))
      json errcode: 99999, errmsg: 'appid 不存在'
    elsif !(user = app.users.find {|user| user.openid == request.user_agent})
      json errcode: 99999, errmsg: '用户不存在, 请在 user_agent 里写 openid'
    else
      code = SecureRandom.hex(10)
      $AUTH_CODES = $AUTH_CODES || {}
      $AUTH_CODES[code] = {
        :actived => true,
        :user => user,
        :app => app,
        :scope => params[:scope],
      }
      redirect "#{params[:redirect_uri]}?code=#{code}"
    end
  end

  get '/sns/oauth2/access_token' do
    if params.keys != ["appid", "secret", "code", "grant_type"]
      json errcode: 99999, errmsg: "参数必须这么来 appid secret code grant_type"
    elsif params[:grant_type] != 'authorization_code'
      json errcode: 99999, errmsg: 'grant_type 必须是 authorization_code'
    elsif !$AUTH_CODES.has_key?(params[:code])
      json errcode: 99999, errmsg: "这个 code #{params[:code]} 不存在"
    elsif $AUTH_CODES[params[:code]][:actived] != true
      json errcode: 99999, errmsg: "这个 code #{params[:code]} 只能用一次"
    elsif params[:appid] != $AUTH_CODES[params[:code]][:app].id
      json errcode: 99999, errmsg: "openid #{params[:openid]} 不对"
    elsif params[:secret] != $AUTH_CODES[params[:code]][:app].secret
      json errcode: 99999, errmsg: "openid #{params[:secret]} 不对"
    else
      $AUTH_CODES[params[:code]][:actived] = false
      json access_token: 'access_token',
           expires_in: 7200,
           refresh_token: 'refresh_token',
           openid: $AUTH_CODES[params[:code]][:user].openid,
           scope: $AUTH_CODES[params[:code]][:scope],
           unionid: 'unionid'
    end
  end
end
