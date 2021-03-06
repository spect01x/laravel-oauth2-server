<?php

namespace RTLer\Oauth2\Repositories;

use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use RTLer\Oauth2\Entities\AccessTokenEntity;
use RTLer\Oauth2\Models\ModelResolver;
use RTLer\Oauth2\Oauth2Server;

class AccessTokenRepository implements AccessTokenRepositoryInterface
{
    /**
     * @var ModelResolver
     */
    protected $modelResolver;

    /**
     * AccessTokenRepository constructor.
     */
    public function __construct()
    {
        $type = app()->make(Oauth2Server::class)
            ->getOptions()['database_type'];
        $this->modelResolver = new ModelResolver($type);
    }

    /**
     * Create a new access token.
     *
     * @param \League\OAuth2\Server\Entities\ClientEntityInterface  $clientEntity
     * @param \League\OAuth2\Server\Entities\ScopeEntityInterface[] $scopes
     * @param mixed                                                 $userIdentifier
     *
     * @return AccessTokenEntityInterface
     */
    public function getNewToken(ClientEntityInterface $clientEntity, array $scopes, $userIdentifier = null)
    {
        return new AccessTokenEntity();
    }

    /**
     * Persists a new access token to permanent storage.
     *
     * @param \League\OAuth2\Server\Entities\AccessTokenEntityInterface $accessTokenEntity
     */
    public function persistNewAccessToken(AccessTokenEntityInterface $accessTokenEntity)
    {
        $accessTokenModel = $this->modelResolver->getModel('AccessTokenModel');

        $newAccessToken = [
            'token'       => $accessTokenEntity->getIdentifier(),
            'client_id'   => $accessTokenEntity->getClient()->getIdentifier(),
            'expire_time' => $accessTokenEntity->getExpiryDateTime(),
        ];

        if (!is_null($accessTokenEntity->getUserIdentifier())) {
            $newAccessToken['user_id'] = $accessTokenEntity->getUserIdentifier();
        }
        $driver = get_class($accessTokenModel::getConnectionResolver()->connection());
        if ($accessTokenEntity->getScopes() !== []) {
            $scopes = array_map(function ($item) {
                return $item->getIdentifier();
            }, $accessTokenEntity->getScopes());

            if ($driver == 'Jenssegers\Mongodb\Connection') {
                $newAccessToken['scopes'] = $scopes;
            } else {
                $newAccessToken['scopes'] = json_encode($scopes);
            }
        }
        $accessTokenModel::create($newAccessToken);
    }

    /**
     * Revoke an access token.
     *
     * @param string $tokenId
     */
    public function revokeAccessToken($tokenId)
    {
        $accessTokenModel = $this->modelResolver->getModel('AccessTokenModel');

        $accessTokenModel::where('token', $tokenId)->delete();
    }

    /**
     * find an access token.
     *
     * @param string $tokenId
     *
     * @return AccessTokenEntity
     */
    public function findAccessToken($tokenId)
    {
        $accessTokenModel = $this->modelResolver->getModel('AccessTokenModel');

        $accessToken = $accessTokenModel::where('token', $tokenId)->first();

        if (is_null($accessToken)) {
            return;
        }

        $accessTokenEntity = new AccessTokenEntity();


        $clientRepository = new ClientRepository();
        $client = $clientRepository->findClientEntity($accessToken->client_id, null, null, false);
        $accessTokenEntity->setClient($client);
        $accessTokenEntity->setUserIdentifier($accessToken->user_id);
        $accessTokenEntity->setIdentifier($accessToken->token);
        $accessTokenEntity->setExpiryDateTime($accessToken->expire_time);

        $driver = get_class($accessTokenModel::getConnectionResolver()->connection());
        $scopes = $accessToken->scopes;
        if ($driver != 'Jenssegers\Mongodb\Connection') {
            $scopes = json_decode($scopes);
        }
        if (!empty($scopes)) {
            $clientRepository = new ScopeRepository();

            foreach ($scopes as $scope) {
                $accessTokenEntity->addScope(
                    $clientRepository->getScopeEntityByIdentifier($scope)
                );
            }
        }

        return $accessTokenEntity;
    }

    /**
     * Check if the access token has been revoked.
     *
     * @param string $tokenId
     *
     * @return bool Return true if this token has been revoked
     */
    public function isAccessTokenRevoked($tokenId)
    {
        $accessTokenModel = $this->modelResolver->getModel('AccessTokenModel');

        return !(bool) $accessTokenModel::where('token', $tokenId)->exists();
    }
}
